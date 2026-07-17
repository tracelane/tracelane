//! Polar checkout endpoint — POST /v1/billing/checkout.
//!
//! Customer onboarding flow:
//!
//!   1. Customer signs in via WorkOS → JWT in `Authorization` header.
//!   2. Customer hits a "Upgrade to <tier>" button in the dashboard.
//!   3. Dashboard POSTs `{ "product_id": "polar_prod_...",
//!                         "success_url": "...", "cancel_url": "..." }`
//!      to this endpoint with the JWT.
//!   4. We resolve the tenant from the JWT, call Polar's
//!      `/checkouts` API with the tenant's `external_customer_id`,
//!      and return the hosted checkout URL.
//!   5. Dashboard redirects the browser to that URL.
//!   6. Customer completes payment on Polar's hosted page.
//!   7. Polar fires `subscription.created` webhook → handler in
//!      `billing/webhook.rs` flips `plan_tier`.
//!
//! Configure: mounted only when `POLAR_ACCESS_TOKEN` is set. Without
//! it, the route stays absent.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use serde::{Deserialize, Serialize};

use super::polar_client::PolarClient;

/// Per-route state. Shares the PolarClient with the portal route.
#[derive(Clone)]
pub struct CheckoutState {
    pub polar: Arc<PolarClient>,
    /// Default redirect target after successful purchase.
    pub default_success_url: String,
    /// Default redirect target after abandoned checkout.
    pub default_cancel_url: String,
}

impl CheckoutState {
    pub fn from_env(polar: Arc<PolarClient>) -> Self {
        let default_success_url = std::env::var("TRACELANE_CHECKOUT_SUCCESS_URL")
            .unwrap_or_else(|_| "https://app.tracelane.dev/billing?status=success".into());
        let default_cancel_url = std::env::var("TRACELANE_CHECKOUT_CANCEL_URL")
            .unwrap_or_else(|_| "https://app.tracelane.dev/billing?status=cancelled".into());
        Self {
            polar,
            default_success_url,
            default_cancel_url,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CheckoutRequest {
    /// Polar product UUID for the desired tier. The dashboard
    /// translates the tier name (e.g. "team") into the product UUID
    /// via a small lookup table — keeps the gateway from needing to
    /// hard-code Polar product IDs.
    pub product_id: String,
    /// Customer email — required by Polar for checkout. Sourced from
    /// the WorkOS user profile by the dashboard before calling us.
    pub customer_email: String,
    /// Where Polar redirects after successful purchase. Optional;
    /// falls back to `TRACELANE_CHECKOUT_SUCCESS_URL`.
    #[serde(default)]
    pub success_url: Option<String>,
    /// Where Polar redirects after abandoned checkout. Optional;
    /// falls back to `TRACELANE_CHECKOUT_CANCEL_URL`.
    #[serde(default)]
    pub cancel_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct CheckoutResponse {
    pub url: String,
}

pub fn routes() -> Router<CheckoutState> {
    Router::new().route("/v1/billing/checkout", post(handler))
}

async fn handler(
    State(state): State<CheckoutState>,
    headers: HeaderMap,
    Json(req): Json<CheckoutRequest>,
) -> impl IntoResponse {
    // 1. Auth — JWT or API key.
    let auth = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(s) => s.to_owned(),
        None => return error(StatusCode::UNAUTHORIZED, "missing Authorization"),
    };
    let claims = match crate::auth::validate_authorization(&auth).await {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "billing checkout auth failed");
            return error(StatusCode::UNAUTHORIZED, "invalid credentials");
        }
    };

    // IDENTITY_TEAM_SPEC §1: billing is owner-only. Members/viewers are denied
    // at the gateway (authoritative), typed `role_forbidden`.
    if !claims.can_admin() {
        return (
            StatusCode::FORBIDDEN,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            crate::auth::role_forbidden_json("owner"),
        )
            .into_response();
    }

    // 2. Basic input validation.
    // product_id must be a UUID-ish opaque string. Polar uses UUIDs
    // but accepts any string for the request; we cap length to bound
    // a request-size attack and refuse obviously bogus shapes.
    if req.product_id.is_empty() || req.product_id.len() > 128 {
        return error(StatusCode::BAD_REQUEST, "product_id is empty or too long");
    }
    if req.customer_email.is_empty() || req.customer_email.len() > 320 {
        return error(
            StatusCode::BAD_REQUEST,
            "customer_email is empty or too long",
        );
    }
    // Soft sanity: must look like an email.
    if !req.customer_email.contains('@') {
        return error(StatusCode::BAD_REQUEST, "customer_email is not an email");
    }

    let success_url = req
        .success_url
        .clone()
        .unwrap_or_else(|| state.default_success_url.clone());
    let cancel_url = req
        .cancel_url
        .clone()
        .unwrap_or_else(|| state.default_cancel_url.clone());

    // A21: refuse to round-trip a success/cancel URL whose host isn't on
    // the operator-controlled allowlist. Defends against a phishing flow
    // where a malicious actor calls the checkout endpoint with a hosted
    // page they control, then Polar's branded checkout redirects to it.
    if let Err(why) = validate_checkout_url(&success_url) {
        tracing::warn!(reason = %why, url = %success_url, "rejecting success_url");
        return error(StatusCode::BAD_REQUEST, "success_url host not allowed");
    }
    if let Err(why) = validate_checkout_url(&cancel_url) {
        tracing::warn!(reason = %why, url = %cancel_url, "rejecting cancel_url");
        return error(StatusCode::BAD_REQUEST, "cancel_url host not allowed");
    }

    // 3. Polar API call.
    match state
        .polar
        .create_checkout(
            &claims.tenant_id.to_string(),
            &req.product_id,
            &req.customer_email,
            &success_url,
            &cancel_url,
        )
        .await
    {
        Ok(url) => (StatusCode::OK, Json(CheckoutResponse { url })).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "Polar checkout creation failed");
            error(StatusCode::BAD_GATEWAY, "checkout unavailable")
        }
    }
}

fn error(status: StatusCode, msg: &str) -> axum::response::Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

/// Hosts permitted as `success_url` / `cancel_url` targets (A21).
///
/// Allowlist permits `tracelane.dev` and any subdomain. Debug builds may
/// set `TRACELANE_BILLING_TEST_ANY_HOST=1` to bypass the check for local
/// integration tests; release builds ignore the env var.
fn validate_checkout_url(url: &str) -> Result<(), &'static str> {
    #[cfg(debug_assertions)]
    if std::env::var("TRACELANE_BILLING_TEST_ANY_HOST").as_deref() == Ok("1") {
        return Ok(());
    }

    let parsed = reqwest::Url::parse(url).map_err(|_| "not a valid URL")?;
    match parsed.scheme() {
        "https" => {}
        "http" if cfg!(debug_assertions) => {}
        _ => return Err("scheme must be https"),
    }
    let host = parsed
        .host_str()
        .ok_or("URL missing host")?
        .to_ascii_lowercase();
    if host == "tracelane.dev" || host.ends_with(".tracelane.dev") {
        Ok(())
    } else {
        Err("host not on the allowlist (*.tracelane.dev)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn checkout_state_defaults_when_env_unset() {
        let _g = ENV_LOCK.lock().expect("env lock");
        let saved_s = std::env::var("TRACELANE_CHECKOUT_SUCCESS_URL").ok();
        let saved_c = std::env::var("TRACELANE_CHECKOUT_CANCEL_URL").ok();
        unsafe {
            std::env::remove_var("TRACELANE_CHECKOUT_SUCCESS_URL");
            std::env::remove_var("TRACELANE_CHECKOUT_CANCEL_URL");
        }
        let state = CheckoutState::from_env(Arc::new(PolarClient::new("polar_pat_fake")));
        assert!(state.default_success_url.contains("status=success"));
        assert!(state.default_cancel_url.contains("status=cancelled"));
        unsafe {
            if let Some(v) = saved_s {
                std::env::set_var("TRACELANE_CHECKOUT_SUCCESS_URL", v);
            }
            if let Some(v) = saved_c {
                std::env::set_var("TRACELANE_CHECKOUT_CANCEL_URL", v);
            }
        }
    }

    #[test]
    fn checkout_response_serializes_url_field() {
        let r = CheckoutResponse {
            url: "https://polar.sh/checkout/x".into(),
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(s.contains("\"url\":\"https://polar.sh/checkout/x\""));
    }

    #[test]
    fn checkout_request_accepts_minimal_shape() {
        let raw = r#"{"product_id": "polar_prod_x", "customer_email": "a@b.com"}"#;
        let req: CheckoutRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.product_id, "polar_prod_x");
        assert!(req.success_url.is_none());
        assert!(req.cancel_url.is_none());
    }
}

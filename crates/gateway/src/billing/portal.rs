//! Polar customer-portal session endpoint — POST /v1/billing/portal.
//!
//! Authenticated tenants exchange their bearer token for a one-shot
//! Polar-hosted portal URL. The portal lets customers manage plan,
//! payment method, invoices, and cancellation without us building a
//! billing UI. Round-trip:
//!
//!   1. Caller authenticates via Authorization: Bearer <jwt|tlane_*>
//!   2. We look up tenant.polar_customer_id in Postgres
//!   3. Polar API: POST /v1/customer-sessions with the customer id
//!   4. Return JSON: { "url": "https://polar.sh/customer-portal/sess_..." }
//!
//! Mounted only when POLAR_ACCESS_TOKEN is set; without it the route
//! stays absent.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
};
use serde::{Deserialize, Serialize};

use super::polar_client::{PolarClient, PolarCustomerId};

#[derive(Clone)]
pub struct PortalState {
    pub polar: Arc<PolarClient>,
    pub return_url: String,
}

/// The built-in return target, used when `TRACELANE_BILLING_RETURN_URL` is unset
/// **or** is set to something off-allowlist. It is a constant rather than an
/// inline literal so the fallback path and the default path cannot drift.
const DEFAULT_RETURN_URL: &str = "https://app.tracelane.dev/billing";

impl PortalState {
    pub fn from_env(polar: Arc<PolarClient>) -> Self {
        let configured = std::env::var("TRACELANE_BILLING_RETURN_URL")
            .unwrap_or_else(|_| DEFAULT_RETURN_URL.into());
        // A misconfigured OPERATOR default is a different failure from a hostile
        // CALLER override, and deserves a different answer. Rejecting it with a
        // 400 would blame the customer for our config; accepting it would make
        // an env var a redirect primitive. So: refuse the value, keep the
        // endpoint working on the safe built-in, and make the mistake loud.
        let return_url = match super::validate_redirect_url(&configured) {
            Ok(()) => configured,
            Err(why) => {
                tracing::error!(
                    reason = %why,
                    configured = %configured,
                    fallback = %DEFAULT_RETURN_URL,
                    "TRACELANE_BILLING_RETURN_URL is not on the billing redirect \
                     allowlist — ignoring it and using the built-in default"
                );
                DEFAULT_RETURN_URL.into()
            }
        };
        Self { polar, return_url }
    }
}

#[derive(Debug, Deserialize)]
pub struct PortalRequest {
    /// Optional override of the configured return URL. Validated against the
    /// billing redirect allowlist (`super::validate_redirect_url`) before use —
    /// an off-host value is a 400, never a redirect target.
    ///
    /// **This field is currently dead on the wire**: Polar's
    /// `/customer-sessions/` endpoint takes no return URL, so
    /// `polar_client::create_customer_portal_session` binds it as `_return_url`
    /// and never places it in the request body. It is still validated, because
    /// the field is public API today and the check must already be in front of
    /// it on the day someone wires it through — which is precisely what the
    /// `TODO: allowlist` that used to live here failed to guarantee (SET-18).
    #[serde(default)]
    pub return_url: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PortalResponse {
    pub url: String,
}

pub fn routes() -> Router<PortalState> {
    Router::new().route("/v1/billing/portal", post(handler))
}

async fn handler(
    State(state): State<PortalState>,
    headers: HeaderMap,
    Json(req): Json<PortalRequest>,
) -> impl IntoResponse {
    // 1. Auth
    let auth = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(s) => s.to_owned(),
        None => return error(StatusCode::UNAUTHORIZED, "missing Authorization"),
    };
    let claims = match crate::auth::validate_authorization(&auth).await {
        Ok(c) => c,
        Err(err) => {
            tracing::warn!(error = %err, "billing portal auth failed");
            return error(StatusCode::UNAUTHORIZED, "invalid credentials");
        }
    };

    // IDENTITY_TEAM_SPEC §1: billing is owner-only (authoritative gateway gate).
    if !claims.can_admin() {
        return (
            StatusCode::FORBIDDEN,
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            crate::auth::role_forbidden_json("owner"),
        )
            .into_response();
    }

    // 2. Look up the tenant's Polar customer id.
    let pool = match crate::db::global_pool() {
        Some(p) => p,
        None => return error(StatusCode::SERVICE_UNAVAILABLE, "billing not configured"),
    };
    let tenant = match crate::db::tenants::get(pool, &claims.tenant_id).await {
        Ok(Some(t)) => t,
        Ok(None) => return error(StatusCode::NOT_FOUND, "tenant not found"),
        Err(err) => {
            tracing::error!(error = %err, "tenant lookup failed");
            return error(StatusCode::INTERNAL_SERVER_ERROR, "tenant lookup failed");
        }
    };
    let customer_id = match tenant.polar_customer_id {
        Some(id) => PolarCustomerId(id),
        None => {
            return error(
                StatusCode::CONFLICT,
                "tenant has no Polar customer — onboard via /v1/billing/checkout first",
            );
        }
    };

    // 3. Resolve the return target, allowlisting a caller-supplied override.
    // `state.return_url` was already validated at startup, so only the override
    // can be hostile here.
    let return_url = match req.return_url {
        Some(candidate) => match super::validate_redirect_url(&candidate) {
            Ok(()) => candidate,
            Err(why) => {
                tracing::warn!(reason = %why, url = %candidate, "rejecting portal return_url");
                return error(StatusCode::BAD_REQUEST, "return_url host not allowed");
            }
        },
        None => state.return_url.clone(),
    };

    // 4. Polar API call.
    match state
        .polar
        .create_customer_portal_session(&customer_id, &return_url)
        .await
    {
        Ok(url) => (StatusCode::OK, Json(PortalResponse { url })).into_response(),
        Err(err) => {
            tracing::error!(error = %err, "Polar portal session creation failed");
            error(StatusCode::BAD_GATEWAY, "billing portal unavailable")
        }
    }
}

fn error(status: StatusCode, msg: &str) -> axum::response::Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialises the tests that mutate process-wide env vars.
    ///
    /// Taken with `into_inner` on poison rather than `expect`: when one test
    /// asserts and panics it poisons the mutex, and every later test then fails
    /// on the LOCK instead of on its own assertion. Falsifying the allowlist
    /// showed exactly that — one real detection reported as three failures, two
    /// of them meaningless. Each test restores the env regardless, so a poisoned
    /// lock carries no unsound state; it only obscures which test caught what.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn portal_state_default_return_url_when_env_unset() {
        let _g = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let saved = std::env::var("TRACELANE_BILLING_RETURN_URL").ok();
        unsafe {
            std::env::remove_var("TRACELANE_BILLING_RETURN_URL");
        }
        let state = PortalState::from_env(Arc::new(PolarClient::new("polar_pat_fake")));
        assert_eq!(state.return_url, "https://app.tracelane.dev/billing");
        if let Some(v) = saved {
            unsafe {
                std::env::set_var("TRACELANE_BILLING_RETURN_URL", v);
            }
        }
    }

    /// Run `f` with `TRACELANE_BILLING_RETURN_URL` set to `value`, restoring the
    /// prior value afterwards. Also clears `TRACELANE_BILLING_TEST_ANY_HOST` for
    /// the duration: that debug bypass makes `validate_redirect_url` return `Ok`
    /// for everything, so a developer with it exported would see these tests
    /// pass while asserting nothing. A guard that can be silently disabled by
    /// the environment is exactly the green-while-broken shape.
    fn with_return_url_env(value: Option<&str>, f: impl FnOnce()) {
        let _g = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let saved = std::env::var("TRACELANE_BILLING_RETURN_URL").ok();
        let saved_bypass = std::env::var("TRACELANE_BILLING_TEST_ANY_HOST").ok();
        unsafe {
            std::env::remove_var("TRACELANE_BILLING_TEST_ANY_HOST");
            match value {
                Some(v) => std::env::set_var("TRACELANE_BILLING_RETURN_URL", v),
                None => std::env::remove_var("TRACELANE_BILLING_RETURN_URL"),
            }
        }
        f();
        unsafe {
            match saved {
                Some(v) => std::env::set_var("TRACELANE_BILLING_RETURN_URL", v),
                None => std::env::remove_var("TRACELANE_BILLING_RETURN_URL"),
            }
            if let Some(v) = saved_bypass {
                std::env::set_var("TRACELANE_BILLING_TEST_ANY_HOST", v);
            }
        }
    }

    #[test]
    fn portal_state_honours_an_on_allowlist_env_override() {
        with_return_url_env(Some("https://billing.tracelane.dev/back"), || {
            let state = PortalState::from_env(Arc::new(PolarClient::new("polar_pat_fake")));
            assert_eq!(state.return_url, "https://billing.tracelane.dev/back");
        });
    }

    /// SET-18, and the falsification for it: this test previously asserted that
    /// `https://custom.example/back` was carried through VERBATIM — the exact
    /// off-host value the allowlist now exists to refuse. It is inverted rather
    /// than deleted so the record shows the guard changed real behaviour.
    #[test]
    fn portal_state_refuses_an_off_allowlist_env_override_and_falls_back() {
        with_return_url_env(Some("https://custom.example/back"), || {
            let state = PortalState::from_env(Arc::new(PolarClient::new("polar_pat_fake")));
            assert_eq!(
                state.return_url, DEFAULT_RETURN_URL,
                "an off-allowlist operator default must be ignored, not honoured"
            );
        });
    }

    /// The property SET-18 exists for, asserted at the validator the handler
    /// calls. Falsified BOTH ways: the attacker-shaped values must fail and the
    /// legitimate ones must pass, so this cannot pass by rejecting everything.
    #[test]
    fn return_url_allowlist_refuses_off_host_and_admits_our_own() {
        let _g = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let saved_bypass = std::env::var("TRACELANE_BILLING_TEST_ANY_HOST").ok();
        unsafe {
            std::env::remove_var("TRACELANE_BILLING_TEST_ANY_HOST");
        }

        for bad in [
            "https://evil.example/phish",
            // The classic allowlist bypasses: suffix-confusion and a
            // subdomain-shaped prefix on someone else's domain.
            "https://tracelane.dev.evil.example/phish",
            "https://nottracelane.dev/phish",
            "https://eviltracelane.dev/phish",
            // Credentials-in-authority: the HOST is evil.example, but a careless
            // `contains("tracelane.dev")` check would admit it.
            "https://tracelane.dev@evil.example/phish",
            "javascript:alert(1)",
            "not a url at all",
            "",
        ] {
            assert!(
                crate::billing::validate_redirect_url(bad).is_err(),
                "expected {bad:?} to be REFUSED as a billing redirect target",
            );
        }

        for good in [
            "https://tracelane.dev/billing",
            "https://app.tracelane.dev/billing",
            "https://billing.tracelane.dev/back?status=done",
            // Host comparison is case-insensitive; DNS is.
            "https://APP.TraceLane.dev/billing",
        ] {
            assert!(
                crate::billing::validate_redirect_url(good).is_ok(),
                "expected {good:?} to be ADMITTED — a guard that refuses everything \
                 is not a guard, it is an outage",
            );
        }

        unsafe {
            if let Some(v) = saved_bypass {
                std::env::set_var("TRACELANE_BILLING_TEST_ANY_HOST", v);
            }
        }
    }

    /// The fallback must itself be on the allowlist. `from_env` returns
    /// `DEFAULT_RETURN_URL` *without* re-validating it — that is deliberate (it
    /// would be a validation loop), which means the constant is the one value in
    /// this file nothing checks at runtime. If someone edits it to an off-host
    /// URL, every deployment silently adopts it as the return target and the
    /// error branch "falls back" to the very thing it was refusing.
    #[test]
    fn the_fallback_default_is_itself_on_the_allowlist() {
        let _g = ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let saved_bypass = std::env::var("TRACELANE_BILLING_TEST_ANY_HOST").ok();
        unsafe {
            std::env::remove_var("TRACELANE_BILLING_TEST_ANY_HOST");
        }
        let verdict = crate::billing::validate_redirect_url(DEFAULT_RETURN_URL);
        unsafe {
            if let Some(v) = saved_bypass {
                std::env::set_var("TRACELANE_BILLING_TEST_ANY_HOST", v);
            }
        }
        assert!(
            verdict.is_ok(),
            "DEFAULT_RETURN_URL ({DEFAULT_RETURN_URL}) is not on the billing \
             redirect allowlist — the safe fallback is not safe",
        );
    }

    /// Structural: the handler must route the caller-supplied override through
    /// the validator. Every other test here exercises `validate_redirect_url`
    /// directly, so deleting the CALL SITE would leave them all green while
    /// reopening SET-18 — the guard would still work and simply never run.
    ///
    /// Needles are split with `concat!` so this test cannot match its own source
    /// (the third time that trap has bitten in this repo — see `usage.rs`).
    #[test]
    fn the_handler_validates_the_caller_supplied_return_url() {
        let src = include_str!("portal.rs");
        let call_site = concat!("validate_", "redirect_url(&candidate)");
        assert!(
            src.contains(call_site),
            "the portal handler must validate a caller-supplied return_url before \
             using it; SET-18 was a TODO sitting exactly here",
        );
        // And the pre-SET-18 shape must not come back: taking the override with
        // no check at all.
        let unguarded = concat!("req.return_url.", "unwrap_or_else");
        assert!(
            !src.contains(unguarded),
            "return_url must not be consumed unvalidated — that was the defect",
        );
    }

    #[test]
    fn portal_response_serializes_url_field() {
        let resp = PortalResponse {
            url: "https://polar.sh/customer-portal/sess_x".into(),
        };
        let s = serde_json::to_string(&resp).unwrap();
        assert!(s.contains("\"url\":\"https://polar.sh/customer-portal/sess_x\""));
    }
}

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

impl PortalState {
    pub fn from_env(polar: Arc<PolarClient>) -> Self {
        let return_url = std::env::var("TRACELANE_BILLING_RETURN_URL")
            .unwrap_or_else(|_| "https://app.tracelane.dev/billing".into());
        Self { polar, return_url }
    }
}

#[derive(Debug, Deserialize)]
pub struct PortalRequest {
    /// Optional override of the configured return URL. The override
    /// must be on a Tracelane-controlled host — we don't validate that
    /// today (TODO: allowlist) but it's the next defence layer.
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

    // 3. Polar API call.
    let return_url = req.return_url.unwrap_or_else(|| state.return_url.clone());
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

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn portal_state_default_return_url_when_env_unset() {
        let _g = ENV_LOCK.lock().expect("env lock");
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

    #[test]
    fn portal_state_honours_env_override() {
        let _g = ENV_LOCK.lock().expect("env lock");
        let saved = std::env::var("TRACELANE_BILLING_RETURN_URL").ok();
        unsafe {
            std::env::set_var(
                "TRACELANE_BILLING_RETURN_URL",
                "https://custom.example/back",
            );
        }
        let state = PortalState::from_env(Arc::new(PolarClient::new("polar_pat_fake")));
        assert_eq!(state.return_url, "https://custom.example/back");
        unsafe {
            match saved {
                Some(v) => std::env::set_var("TRACELANE_BILLING_RETURN_URL", v),
                None => std::env::remove_var("TRACELANE_BILLING_RETURN_URL"),
            }
        }
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

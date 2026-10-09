//! `GET /v1/openapi.json` — the control API's OpenAPI 3.1 description (`OG-60` Part A,
//! `specs/OG-60-openapi-and-gateway-settings.md`).
//!
//! The body is `include_str!` of the checked-in `crates/gateway/openapi/control.v1.json`, which
//! `scripts/ci/build-openapi.py --check` proves is exactly what the generator builds from
//! `CONTROL_ROUTES`, `MATRIX`, the mounted route table and the fragments — so the served bytes
//! cannot differ from the reviewed file.
//!
//! **Public by design, like `/v1/audit/pubkey`:** the document holds route shapes, roles and
//! error codes — no tenant data, no secret. The route is mounted by `audit_pubkey::routes()`
//! (`audit_pubkey::openapi_handler`), so it shares that module's process-global rate bucket (the
//! same no-unspoofable-peer-IP constraint: `axum::serve` runs without connect-info).
//!
//! # Errors
//! `429 {"error":"rate_limited"}` + `Retry-After` when the global bucket is empty. Fail-OPEN
//! otherwise: a documentation route has no security path to fail closed on.

use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::auth::workos_webhook::WebhookRateLimiter;
use crate::rate_limiter::RateLimitDecision;

/// The generated document, embedded at build time.
const DOCUMENT: &str = include_str!("../openapi/control.v1.json");

/// The response for one request, charged to `rate`.
pub fn respond(rate: &WebhookRateLimiter) -> Response {
    if let RateLimitDecision::Throttle { retry_after_secs } = rate.check() {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry_after_secs.to_string())],
            axum::Json(serde_json::json!({ "error": "rate_limited" })),
        )
            .into_response();
    }
    (
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "public, max-age=300"),
        ],
        DOCUMENT,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn serves_exactly_the_checked_in_bytes() {
        let res = respond(&WebhookRateLimiter::new(600));
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()
                .get(header::CONTENT_TYPE)
                .map(|v| v.as_bytes()),
            Some(b"application/json".as_slice())
        );
        let body = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        assert_eq!(body.as_ref(), DOCUMENT.as_bytes());
        let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(doc["openapi"], "3.1.0");
        assert!(doc["paths"]["/v1/controls/pause"]["post"].is_object());
    }

    #[test]
    fn the_global_bucket_throttles_with_retry_after() {
        let rate = WebhookRateLimiter::new(1);
        assert_eq!(respond(&rate).status(), StatusCode::OK);
        let res = respond(&rate);
        assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(res.headers().contains_key(header::RETRY_AFTER));
    }
}

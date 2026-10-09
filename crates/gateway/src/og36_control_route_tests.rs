//! `OG-34` / `OG-36` — the gate on the EXISTING control routes, driven through
//! their real routers behind the real B-594 layer.
//!
//! The test state has no Postgres, so a request that PASSES the gate reaches the
//! store and answers 503 (`no_control_plane` / `control plane unavailable`); a
//! request the gate REFUSES answers 403 before it. That difference is the proof.
//! Written red-first: before OG-34/OG-36 every case below that expects 403 answered
//! 503 — a viewer could reach the spend-ceiling store, and an admin off the
//! allowlist reached every policy store.

use std::net::SocketAddr;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::connect_info::MockConnectInfo,
    http::{Method, Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use tracelane_shared::TenantId;
use uuid::Uuid;

use crate::auth::scope::{KeyScope, Scope};
use crate::auth::{AuthMethod, Claims, Role};
use crate::control_plane::test_overrides;
use crate::db::admin_security::AdminAccess;

fn who(auth_method: AuthMethod, role: Option<Role>) -> Claims {
    Claims {
        tenant_id: TenantId::from_jwt_claim(Uuid::from_u128(0x0636)),
        sub: "user_og36_routes".into(),
        auth_method,
        role,
        key_scope: KeyScope::LegacyFullSurface,
        budget_usd_monthly: None,
        rate_limit_rpm: None,
        budget_reset: crate::spend::BudgetReset::Monthly,
        governance: None,
    }
}

fn admin() -> Claims {
    who(AuthMethod::JwtBearer, Some(Role::Owner))
}

fn allowlist(cidrs: &[&str], sso: bool) -> Option<Result<AdminAccess, ()>> {
    Some(Ok(AdminAccess {
        admin_ip_allowlist: cidrs.iter().map(|c| (*c).to_owned()).collect(),
        sso_required: sso,
        updated_at: None,
        updated_by: None,
    }))
}

fn state() -> crate::server::AppState {
    crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().expect("registry"))
}

/// Every control router the gateway mounts with a control plane, behind the real
/// B-594 layer, served from `peer`.
fn app(peer: &str) -> Router {
    let s = state();
    Router::new()
        .merge(crate::billing::usage::routes(s.clone()))
        .merge(crate::model_alias_routes::router(s.clone()))
        .merge(crate::routing::routes::router(s.clone()))
        .merge(crate::workspace_capture_routes::router(s.clone()))
        .merge(crate::cache_routes::router(s.clone()))
        .merge(crate::otel_export_routes::router(s.clone()))
        .merge(crate::guardrail::tool_pins_api::router(s.clone()))
        .merge(crate::byok_api::provider_keys_api::router(s))
        .layer(axum::middleware::from_fn_with_state(
            crate::preauth_limiter::PreAuthLimiter::new(60),
            crate::preauth_limiter::layer,
        ))
        .layer(MockConnectInfo(SocketAddr::new(
            peer.parse().unwrap(),
            4000,
        )))
}

async fn send(peer: &str, method: Method, uri: &str, body: Option<Value>) -> (StatusCode, String) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", "Bearer test-token-not-a-real-jwt");
    let body = match body {
        Some(v) => {
            req = req.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let resp = app(peer).oneshot(req.body(body).unwrap()).await.unwrap();
    let s = resp.status();
    (
        s,
        String::from_utf8(to_bytes(resp.into_body(), 1 << 16).await.unwrap().to_vec()).unwrap(),
    )
}

/// One request per registered mutating control route this test can mount, each
/// with a body the route accepts up to its store.
fn control_calls() -> Vec<(Method, &'static str, Option<Value>)> {
    vec![
        (
            Method::PUT,
            "/v1/billing/ceiling",
            Some(json!({"usd": 10.0})),
        ),
        (Method::DELETE, "/v1/billing/promotion-freeze", None),
        (
            Method::PUT,
            "/v1/model-aliases",
            Some(json!({"alias": "fast", "target_model": "gpt-4o-mini"})),
        ),
        (Method::DELETE, "/v1/model-aliases?alias=fast", None),
        (
            Method::PUT,
            "/v1/gateway/failover",
            Some(json!({"enabled": false})),
        ),
        (
            Method::PUT,
            "/v1/routing",
            Some(
                json!({"doc": {"virtual_models": {"fast": {"targets": [{"model": "gpt-4o-mini"}]}}}}),
            ),
        ),
        (
            Method::PUT,
            "/v1/workspace/capture",
            Some(json!({"input": true, "output": true})),
        ),
        (
            Method::POST,
            "/v1/guardrails/tool-pins",
            Some(json!({"tool_name": "t", "schema": {"type": "object"}})),
        ),
        (
            Method::POST,
            "/v1/guardrails/tool-pins/approve",
            Some(json!({"tool_name": "t", "def_hash": "h"})),
        ),
        (Method::DELETE, "/v1/guardrails/tool-pins/t", None),
        (
            Method::POST,
            "/v1/byok/provider-keys",
            Some(
                json!({"provider_id": "openai", "plaintext": "sk-test-not-a-real-key-000000000000"}),
            ),
        ),
        (Method::DELETE, "/v1/byok/provider-keys/openai", None),
        // OG-51: the response-cache controls.
        (
            Method::PUT,
            "/v1/cache/settings",
            Some(json!({"mode": "off"})),
        ),
        (
            Method::POST,
            "/v1/cache/invalidate",
            Some(json!({"scope": "workspace"})),
        ),
        // OG-50: the OTLP span exports.
        (
            Method::POST,
            "/v1/exports/otel",
            Some(json!({"name": "n", "url": "https://collector.example.com/v1/traces"})),
        ),
        (
            Method::PATCH,
            "/v1/exports/otel/00000000-0000-4000-8000-000000000050",
            Some(json!({"enabled": false})),
        ),
        (
            Method::DELETE,
            "/v1/exports/otel/00000000-0000-4000-8000-000000000050",
            None,
        ),
        (
            Method::POST,
            "/v1/exports/otel/00000000-0000-4000-8000-000000000050/test",
            None,
        ),
    ]
}

#[tokio::test]
async fn og34_a_viewer_developer_or_unrecognised_slug_cannot_move_the_spend_ceiling() {
    let _g = test_overrides::Guard::new(Some(Ok(AdminAccess::default())), None, None);
    for role in [Some(Role::Viewer), Some(Role::Member), None] {
        let _c = crate::auth::test_claims::Guard::set(who(AuthMethod::JwtBearer, role));
        for (method, uri) in [
            (Method::PUT, "/v1/billing/ceiling"),
            (Method::DELETE, "/v1/billing/promotion-freeze"),
        ] {
            let body = (method == Method::PUT).then(|| json!({"usd": 10.0}));
            let (s, b) = send("198.51.100.7", method.clone(), uri, body).await;
            assert_eq!(s, StatusCode::FORBIDDEN, "{role:?} {method} {uri}: {b}");
            assert!(b.contains("edit_budgets"), "{b}");
        }
    }
}

#[tokio::test]
async fn og34_the_billing_role_and_an_admin_scoped_key_may_set_the_ceiling() {
    let _g = test_overrides::Guard::new(Some(Ok(AdminAccess::default())), None, None);
    let mut key = who(AuthMethod::ApiKey, None);
    key.key_scope = KeyScope::Scoped([Scope::Admin].into_iter().collect());
    for c in [
        who(AuthMethod::JwtBearer, Some(Role::Billing)),
        admin(),
        key,
    ] {
        let _c = crate::auth::test_claims::Guard::set(c);
        let (s, b) = send(
            "198.51.100.7",
            Method::PUT,
            "/v1/billing/ceiling",
            Some(json!({"usd": 10.0})),
        )
        .await;
        assert_eq!(
            s,
            StatusCode::SERVICE_UNAVAILABLE,
            "gate passed, no store: {b}"
        );
    }
}

#[tokio::test]
async fn og36_every_control_route_refuses_an_admin_outside_the_allowlist() {
    let _c = crate::auth::test_claims::Guard::set(admin());
    let _g = test_overrides::Guard::new(allowlist(&["203.0.113.0/24"], false), None, None);
    for (method, uri, body) in control_calls() {
        let (s, b) = send("198.51.100.7", method.clone(), uri, body).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{method} {uri}: {b}");
        assert!(b.contains("admin_ip_not_allowed"), "{method} {uri}: {b}");
    }
}

#[tokio::test]
async fn og36_every_control_route_admits_an_admin_inside_the_allowlist() {
    let _c = crate::auth::test_claims::Guard::set(admin());
    let _g = test_overrides::Guard::new(allowlist(&["203.0.113.0/24"], false), None, None);
    for (method, uri, body) in control_calls() {
        let (s, b) = send("203.0.113.9", method.clone(), uri, body).await;
        assert_ne!(s, StatusCode::FORBIDDEN, "{method} {uri}: {b}");
    }
}

#[tokio::test]
async fn og36_every_control_route_refuses_a_password_session_under_sso_required() {
    let _c = crate::auth::test_claims::Guard::set(admin());
    let _g = test_overrides::Guard::new(allowlist(&[], true), Some(Ok(false)), None);
    for (method, uri, body) in control_calls() {
        let (s, b) = send("198.51.100.7", method.clone(), uri, body).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{method} {uri}: {b}");
        assert!(b.contains("sso_required"), "{method} {uri}: {b}");
    }
}

#[tokio::test]
async fn og36_an_unreadable_policy_refuses_every_control_route() {
    let _c = crate::auth::test_claims::Guard::set(admin());
    let _g = test_overrides::Guard::new(Some(Err(())), None, None);
    for (method, uri, body) in control_calls() {
        let (s, b) = send("198.51.100.7", method.clone(), uri, body).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{method} {uri}: {b}");
        assert!(
            b.contains("control_settings_unavailable"),
            "{method} {uri}: {b}"
        );
    }
}

#[tokio::test]
async fn og36_inference_and_read_routes_ignore_the_admin_allowlist() {
    // The allowlist is an ADMIN-plane control: a spend read from off the list is
    // still answered (here 503 — no store — rather than 403).
    let _c = crate::auth::test_claims::Guard::set(admin());
    let _g =
        test_overrides::Guard::new(allowlist(&["203.0.113.0/24"], true), Some(Ok(false)), None);
    let (s, b) = send("198.51.100.7", Method::GET, "/v1/billing/usage", None).await;
    assert_ne!(s, StatusCode::FORBIDDEN, "{b}");
}

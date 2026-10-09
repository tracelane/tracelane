//! `OG-34` / `OG-35` / `OG-36` — the admin-plane gate, driven through real routers.
//!
//! The IP-allowlist tests mount the REAL B-594 layer (`preauth_limiter::layer`) with
//! `MockConnectInfo`, so the address under test is derived exactly as production
//! derives it — including from a public peer that spoofs every forwarding header.

use std::net::SocketAddr;

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::connect_info::MockConnectInfo,
    http::{HeaderMap, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
};
use ring::hmac;
use tower::ServiceExt as _;
use tracelane_shared::TenantId;
use uuid::Uuid;

use super::*;
use crate::auth::scope::KeyScope;
use crate::auth::{AuthMethod, Role};
use crate::db::admin_security::AdminAccess;

const TOKEN: &str = "test-session-token-not-a-real-jwt";

fn claims(auth_method: AuthMethod, role: Option<Role>) -> Claims {
    Claims {
        tenant_id: TenantId::from_jwt_claim(Uuid::from_u128(0x0634)),
        sub: "user_og36".into(),
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
    claims(AuthMethod::JwtBearer, Some(Role::Owner))
}

fn access(cidrs: &[&str], sso: bool) -> AdminAccess {
    AdminAccess {
        admin_ip_allowlist: cidrs.iter().map(|c| (*c).to_owned()).collect(),
        sso_required: sso,
        updated_at: None,
        updated_by: None,
    }
}

fn leak_key(secret: &str) -> &'static hmac::Key {
    Box::leak(Box::new(hmac::Key::new(
        hmac::HMAC_SHA256,
        secret.as_bytes(),
    )))
}

/// A router whose one route is `require_control(cap)` for `who`, behind the REAL
/// B-594 layer, served as if from `peer`.
fn gate_router(who: Claims, cap: impl Into<ControlGate>, peer: Option<&str>) -> Router {
    let gate: ControlGate = cap.into();
    let handler = move |headers: HeaderMap| {
        let who = who.clone();
        async move {
            match require_control(&who, gate, &headers).await {
                Ok(a) => (
                    StatusCode::NO_CONTENT,
                    [(
                        "x-ip",
                        a.client_ip.map(|i| i.to_string()).unwrap_or_default(),
                    )],
                )
                    .into_response(),
                Err(r) => r.into_response(),
            }
        }
    };
    let r =
        Router::new()
            .route("/probe", get(handler))
            .layer(axum::middleware::from_fn_with_state(
                crate::preauth_limiter::PreAuthLimiter::new(60),
                crate::preauth_limiter::layer,
            ));
    match peer {
        Some(p) => r.layer(MockConnectInfo(SocketAddr::new(p.parse().unwrap(), 4000))),
        None => r,
    }
}

async fn call(router: Router, headers: &[(&str, &str)]) -> (StatusCode, String, String) {
    let mut req = Request::get("/probe").header("authorization", format!("Bearer {TOKEN}"));
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp: Response = router
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let ip = resp
        .headers()
        .get("x-ip")
        .map(|v| v.to_str().unwrap().to_owned())
        .unwrap_or_default();
    let body =
        String::from_utf8(to_bytes(resp.into_body(), 1 << 16).await.unwrap().to_vec()).unwrap();
    (status, body, ip)
}

// ── OG-34: the capability half of the gate ─────────────────────────────────────

#[tokio::test]
async fn og34_each_role_is_refused_the_control_capabilities_it_lacks() {
    let _g = test_overrides::Guard::new(Some(Ok(AdminAccess::default())), None, None);
    let h = HeaderMap::new();
    let cases: &[(Option<Role>, AuthMethod, Capability, bool)] = &[
        (
            Some(Role::Viewer),
            AuthMethod::JwtBearer,
            Capability::EditBudgets,
            false,
        ),
        (
            Some(Role::Viewer),
            AuthMethod::JwtBearer,
            Capability::MintKeys,
            false,
        ),
        (
            Some(Role::Member),
            AuthMethod::JwtBearer,
            Capability::EditPolicies,
            false,
        ),
        (
            Some(Role::Member),
            AuthMethod::JwtBearer,
            Capability::MintKeys,
            true,
        ),
        (
            Some(Role::Billing),
            AuthMethod::JwtBearer,
            Capability::EditBudgets,
            true,
        ),
        (
            Some(Role::Billing),
            AuthMethod::JwtBearer,
            Capability::ManageSecurity,
            false,
        ),
        (None, AuthMethod::JwtBearer, Capability::ManageAlerts, false),
        (
            Some(Role::Owner),
            AuthMethod::JwtBearer,
            Capability::ManageSecurity,
            true,
        ),
        (None, AuthMethod::ApiKey, Capability::ManageSecurity, false),
        (
            None,
            AuthMethod::ApiKey,
            Capability::ReadControlAudit,
            false,
        ),
        (None, AuthMethod::Mtls, Capability::ViewSpend, false),
    ];
    for (role, method, cap, allowed) in cases {
        let r = require_control(&claims(*method, *role), *cap, &h).await;
        assert_eq!(r.is_ok(), *allowed, "{method:?}/{role:?} → {cap:?}");
        if let Err(refusal) = r {
            assert_eq!(refusal.status, StatusCode::FORBIDDEN);
            assert!(
                refusal.body.contains("\"role_forbidden\""),
                "{}",
                refusal.body
            );
            assert!(refusal.body.contains(cap.slug()), "{}", refusal.body);
        }
    }
}

#[tokio::test]
async fn og35_the_actor_carries_role_method_request_id_and_user_agent_never_the_token() {
    let _g = test_overrides::Guard::new(Some(Ok(AdminAccess::default())), None, None);
    let mut h = HeaderMap::new();
    h.insert(header::USER_AGENT, "x".repeat(1000).parse().unwrap());
    h.insert(
        header::AUTHORIZATION,
        format!("Bearer {TOKEN}").parse().unwrap(),
    );
    let a = require_control(&admin(), Capability::EditPolicies, &h)
        .await
        .unwrap();
    assert_eq!(a.audit.role, "admin");
    assert_eq!(a.audit.auth_method, "workos_session");
    assert_eq!(a.audit.sub, "user_og36");
    assert!(Uuid::parse_str(&a.audit.request_id).is_ok());
    assert_eq!(
        a.audit.user_agent.as_deref().map(str::len),
        Some(USER_AGENT_MAX)
    );
    let b = require_control(&admin(), Capability::EditPolicies, &h)
        .await
        .unwrap();
    assert_ne!(a.audit.request_id, b.audit.request_id, "minted per request");
}

#[tokio::test]
async fn og36_an_unreadable_policy_refuses_503_never_allows() {
    let _g = test_overrides::Guard::new(Some(Err(())), None, None);
    let r = require_control(&admin(), Capability::EditPolicies, &HeaderMap::new()).await;
    let refusal = r.expect_err("an unreadable policy must refuse");
    assert_eq!(refusal.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(refusal.body.contains("control_settings_unavailable"));
}

#[tokio::test]
async fn og36_a_stored_non_cidr_entry_refuses_rather_than_being_skipped() {
    let _g = test_overrides::Guard::new(Some(Ok(access(&["not-a-cidr"], false))), None, None);
    let (status, body, _) = call(
        gate_router(admin(), Capability::EditPolicies, Some("10.0.0.2")),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert!(body.contains("control_settings_invalid"));
}

// ── OG-36: the IP allowlist, through the REAL B-594 derivation ─────────────────

#[tokio::test]
async fn og36_a_public_peer_spoofing_every_forwarding_header_is_refused() {
    let _g = test_overrides::Guard::new(Some(Ok(access(&["203.0.113.0/24"], false))), None, None);
    let (status, body, _) = call(
        gate_router(admin(), Capability::EditPolicies, Some("198.51.100.7")),
        &[
            ("cf-connecting-ip", "203.0.113.5"),
            ("x-forwarded-for", "203.0.113.5"),
            ("x-real-ip", "203.0.113.5"),
        ],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("admin_ip_not_allowed"), "{body}");
    // rev5 M4: the refusal must NOT echo the address it checked. Behind the dashboard the
    // address is a shared Cloudflare Workers egress IP when the attestation is missing, and
    // printing it invites an owner to allowlist an address every Worker on the internet
    // shares. It is logged server-side (with the tenant) instead.
    assert!(
        !body.contains("198.51.100.7") && !body.contains("client_ip"),
        "the refusal must not echo the checked address: {body}"
    );
}

#[tokio::test]
async fn og36_an_allowlisted_public_peer_is_admitted() {
    let _g = test_overrides::Guard::new(Some(Ok(access(&["203.0.113.0/24"], false))), None, None);
    let (status, body, ip) = call(
        gate_router(admin(), Capability::EditPolicies, Some("203.0.113.9")),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "{body}");
    assert_eq!(ip, "203.0.113.9");
}

#[tokio::test]
async fn og36_behind_a_trusted_hop_the_proxy_header_decides() {
    let _g = test_overrides::Guard::new(Some(Ok(access(&["203.0.113.0/24"], false))), None, None);
    let (ok, _, ip) = call(
        gate_router(admin(), Capability::EditPolicies, Some("10.0.0.2")),
        &[("cf-connecting-ip", "203.0.113.5")],
    )
    .await;
    assert_eq!(ok, StatusCode::NO_CONTENT);
    assert_eq!(ip, "203.0.113.5");
    let (no, body, _) = call(
        gate_router(admin(), Capability::EditPolicies, Some("10.0.0.2")),
        &[("cf-connecting-ip", "198.51.100.1")],
    )
    .await;
    assert_eq!(no, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test]
async fn og36_an_unprovable_address_is_refused_when_an_allowlist_exists() {
    let _g = test_overrides::Guard::new(Some(Ok(access(&["0.0.0.0/0"], false))), None, None);
    // No layer at all: the request never had an address derived for it.
    let r = require_control(&admin(), Capability::EditPolicies, &HeaderMap::new()).await;
    assert_eq!(
        r.expect_err("unknown address").status,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn og36_no_allowlist_means_any_address() {
    let _g = test_overrides::Guard::new(Some(Ok(AdminAccess::default())), None, None);
    let (status, _, _) = call(
        gate_router(admin(), Capability::EditPolicies, Some("198.51.100.7")),
        &[],
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn og36_the_dashboard_attestation_is_honoured_only_when_it_verifies() {
    let key = leak_key("og36-test-attestation-secret-do-not-use-in-prod");
    let now = Utc::now().timestamp();
    let good = attest::sign(key, "203.0.113.5", now, TOKEN);
    let worker_peer = Some("198.51.100.7"); // the Worker's egress, not on the list
    let pol = Some(Ok(access(&["203.0.113.0/24"], false)));

    // Verifies → the attested browser address is the one checked.
    {
        let _g = test_overrides::Guard::new(pol.clone(), None, Some(key));
        let (s, body, ip) = call(
            gate_router(admin(), Capability::EditPolicies, worker_peer),
            &[(attest::HEADER, &good)],
        )
        .await;
        assert_eq!(s, StatusCode::NO_CONTENT, "{body}");
        assert_eq!(ip, "203.0.113.5");
    }
    // No secret configured → the header is IGNORED (never trusted).
    {
        let _g = test_overrides::Guard::new(pol.clone(), None, None);
        let (s, _, _) = call(
            gate_router(admin(), Capability::EditPolicies, worker_peer),
            &[(attest::HEADER, &good)],
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
    }
    // Signed with another secret, bound to another token, stale, or tampered → ignored.
    let other = leak_key("a-different-secret-of-at-least-32-bytes!!");
    let forged = attest::sign(other, "203.0.113.5", now, TOKEN);
    let other_token = attest::sign(key, "203.0.113.5", now, "some-other-token");
    let stale = attest::sign(key, "203.0.113.5", now - 3_600, TOKEN);
    let tampered = good.replace("203.0.113.5", "203.0.113.6");
    for bad in [&forged, &other_token, &stale, &tampered] {
        let _g = test_overrides::Guard::new(pol.clone(), None, Some(key));
        let (s, _, _) = call(
            gate_router(admin(), Capability::EditPolicies, worker_peer),
            &[(attest::HEADER, bad)],
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{bad} must not be honoured");
    }
}

// ── OG-36: SSO-required ────────────────────────────────────────────────────────

#[tokio::test]
async fn og36_sso_required_refuses_a_non_sso_session_and_admits_an_sso_one() {
    let pol = Some(Ok(access(&[], true)));
    {
        let _g = test_overrides::Guard::new(pol.clone(), Some(Ok(false)), None);
        let e = require_control(&admin(), Capability::EditPolicies, &HeaderMap::new())
            .await
            .expect_err("password session under SSO-required");
        assert_eq!(e.status, StatusCode::FORBIDDEN);
        assert!(e.body.contains("sso_required"));
    }
    {
        let _g = test_overrides::Guard::new(pol.clone(), Some(Ok(true)), None);
        assert!(
            require_control(&admin(), Capability::EditPolicies, &HeaderMap::new())
                .await
                .is_ok()
        );
    }
    {
        let _g = test_overrides::Guard::new(pol.clone(), Some(Err(())), None);
        let e = require_control(&admin(), Capability::EditPolicies, &HeaderMap::new())
            .await
            .expect_err("an SSO lookup that cannot complete must refuse");
        assert_eq!(e.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(e.body.contains("sso_unverifiable"));
    }
    {
        // A machine credential has no SSO session; its scopes govern it.
        let _g = test_overrides::Guard::new(pol, Some(Ok(false)), None);
        let key = claims(AuthMethod::ApiKey, None);
        assert!(
            require_control(&key, Capability::WritePrompts, &HeaderMap::new())
                .await
                .is_ok()
        );
    }
}

#[test]
fn og36_the_sessions_page_verdict_requires_an_active_sso_session() {
    let page: sso::SessionPage = serde_json::from_value(json!({
        "data": [
            {"object":"session","id":"session_sso","auth_method":"sso","status":"active","organization_id":"org_this"},
            {"object":"session","id":"session_pw","auth_method":"password","status":"active","organization_id":"org_this"},
            {"object":"session","id":"session_imp","auth_method":"impersonation","status":"active","organization_id":"org_this"},
            {"object":"session","id":"session_old","auth_method":"sso","status":"revoked","organization_id":"org_this"},
            {"object":"session","id":"session_other_org","auth_method":"sso","status":"active","organization_id":"org_other"},
            {"object":"session","id":"session_no_org","auth_method":"sso","status":"active","organization_id":null}
        ],
        "list_metadata": {"before": null, "after": null}
    }))
    .unwrap();
    let org = Some("org_this");
    assert_eq!(sso::verdict(&page, "session_sso", org), Some(true));
    assert_eq!(sso::verdict(&page, "session_pw", org), Some(false));
    assert_eq!(sso::verdict(&page, "session_imp", org), Some(false));
    assert_eq!(sso::verdict(&page, "session_old", org), Some(false));
    assert_eq!(sso::verdict(&page, "session_missing", org), None);
    // rev5 L3: an SSO session signed in to ANOTHER organization (or none) is not this
    // workspace's SSO, and a token with no `org_id` to bind to never is.
    assert_eq!(sso::verdict(&page, "session_other_org", org), Some(false));
    assert_eq!(sso::verdict(&page, "session_no_org", org), Some(false));
    assert_eq!(sso::verdict(&page, "session_sso", None), Some(false));
}

// ── OG-36: the settings route and its lock-out guard ───────────────────────────

/// A pool that can never connect: a route that reaches the store answers 503,
/// which is how these tests see that the guard ran BEFORE the store.
fn dead_pool() -> DbPool {
    let mut cfg = deadpool_postgres::Config::new();
    cfg.host = Some("127.0.0.1".into());
    cfg.port = Some(1);
    cfg.user = Some("nobody".into());
    cfg.dbname = Some("none".into());
    cfg.create_pool(
        Some(deadpool_postgres::Runtime::Tokio1),
        tokio_postgres::NoTls,
    )
    .unwrap()
}

fn settings_router(peer: &str) -> Router {
    router(dead_pool())
        .layer(axum::middleware::from_fn_with_state(
            crate::preauth_limiter::PreAuthLimiter::new(60),
            crate::preauth_limiter::layer,
        ))
        .layer(MockConnectInfo(SocketAddr::new(
            peer.parse().unwrap(),
            4000,
        )))
}

async fn put_settings(peer: &str, body: Value) -> (StatusCode, String) {
    let req = Request::put("/v1/security/admin-access")
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = settings_router(peer).oneshot(req).await.unwrap();
    let s = resp.status();
    (
        s,
        String::from_utf8(to_bytes(resp.into_body(), 1 << 16).await.unwrap().to_vec()).unwrap(),
    )
}

#[tokio::test]
async fn og36_the_owner_cannot_lock_themselves_out_by_ip_without_confirming() {
    let _c = crate::auth::test_claims::Guard::set(admin());
    let _g = test_overrides::Guard::new(Some(Ok(AdminAccess::default())), None, None);
    let (s, body) = put_settings(
        "198.51.100.7",
        json!({"admin_ip_allowlist": ["203.0.113.0/24"]}),
    )
    .await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert!(
        body.contains("would_lock_you_out") && body.contains("\"ip\""),
        "{body}"
    );
    assert!(body.contains("198.51.100.7"), "{body}");
    // Including the caller's own address passes the guard (and reaches the store).
    let (s, body) = put_settings(
        "198.51.100.7",
        json!({"admin_ip_allowlist": ["203.0.113.0/24", "198.51.100.0/24"]}),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::SERVICE_UNAVAILABLE,
        "guard passed, store unreachable: {body}"
    );
    // So does the explicit acknowledgement.
    let (s, _) = put_settings(
        "198.51.100.7",
        json!({"admin_ip_allowlist": ["203.0.113.0/24"], "acknowledge_lockout": true}),
    )
    .await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn og36_requiring_sso_from_a_non_sso_session_needs_confirmation() {
    let _c = crate::auth::test_claims::Guard::set(admin());
    let _g = test_overrides::Guard::new(Some(Ok(AdminAccess::default())), Some(Ok(false)), None);
    let (s, body) = put_settings("198.51.100.7", json!({"sso_required": true})).await;
    assert_eq!(s, StatusCode::CONFLICT, "{body}");
    assert!(body.contains("\"sso\""), "{body}");
    let (s, _) = put_settings(
        "198.51.100.7",
        json!({"sso_required": true, "acknowledge_lockout": true}),
    )
    .await;
    assert_eq!(
        s,
        StatusCode::SERVICE_UNAVAILABLE,
        "guard passed, store unreachable"
    );
}

#[tokio::test]
async fn og36_invalid_allowlists_are_400_before_anything_is_written() {
    let _c = crate::auth::test_claims::Guard::set(admin());
    let _g = test_overrides::Guard::new(Some(Ok(AdminAccess::default())), None, None);
    let too_many: Vec<String> = (0..=policy().admin_access.max_ip_allowlist_entries)
        .map(|i| format!("10.{}.{}.0/24", i / 256, i % 256))
        .collect();
    for bad in [
        json!({"admin_ip_allowlist": ["203.0.113.5/24"]}), // host bits set
        json!({"admin_ip_allowlist": ["example.com"]}),
        json!({"admin_ip_allowlist": ["10.0.0.0/33"]}),
        json!({"admin_ip_allowlist": too_many}),
        json!({"admin_ip_allowlist": [], "surprise": true}),
    ] {
        let (s, body) = put_settings("198.51.100.7", bad.clone()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad} → {body}");
    }
}

#[tokio::test]
async fn og36_only_an_admin_session_reads_or_changes_the_policy() {
    let _g = test_overrides::Guard::new(Some(Ok(AdminAccess::default())), None, None);
    for who in [
        claims(AuthMethod::JwtBearer, Some(Role::Member)),
        claims(AuthMethod::JwtBearer, Some(Role::Billing)),
        claims(AuthMethod::JwtBearer, Some(Role::Viewer)),
        claims(AuthMethod::JwtBearer, None),
        claims(AuthMethod::ApiKey, None),
    ] {
        let _c = crate::auth::test_claims::Guard::set(who.clone());
        let (s, body) = put_settings("198.51.100.7", json!({"sso_required": false})).await;
        assert_eq!(
            s,
            StatusCode::FORBIDDEN,
            "{:?}/{:?}: {body}",
            who.auth_method,
            who.role
        );
        let req = Request::get("/v1/security/admin-access")
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap();
        let resp = settings_router("198.51.100.7").oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}

// ── OG-35: the dashboard's record endpoint ─────────────────────────────────────

async fn post_change(peer: &str, body: Value) -> (StatusCode, String) {
    let req = Request::post("/v1/audit/control-changes")
        .header("authorization", format!("Bearer {TOKEN}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = settings_router(peer).oneshot(req).await.unwrap();
    let s = resp.status();
    (
        s,
        String::from_utf8(to_bytes(resp.into_body(), 1 << 16).await.unwrap().to_vec()).unwrap(),
    )
}

#[tokio::test]
async fn og35_the_record_endpoint_accepts_only_dashboard_actions_behind_their_capability() {
    let _g = test_overrides::Guard::new(Some(Ok(AdminAccess::default())), None, None);
    {
        let _c = crate::auth::test_claims::Guard::set(admin());
        let (s, body) = post_change(
            "198.51.100.7",
            json!({"action": "api_key.create", "target_id": "k"}),
        )
        .await;
        assert_eq!(
            s,
            StatusCode::BAD_REQUEST,
            "a gateway action cannot be forged here: {body}"
        );
        let (s, _) = post_change(
            "198.51.100.7",
            json!({"action": "member.role_change", "target_id": "om_1", "target_type": "x"}),
        )
        .await;
        assert_eq!(
            s,
            StatusCode::BAD_REQUEST,
            "target_type is derived, never accepted"
        );
        let (s, _) = post_change(
            "198.51.100.7",
            json!({"action": "member.role_change", "target_id": "om_1"}),
        )
        .await;
        assert_eq!(
            s,
            StatusCode::SERVICE_UNAVAILABLE,
            "gate passed, store unreachable"
        );
    }
    for who in [
        claims(AuthMethod::JwtBearer, Some(Role::Member)),
        claims(AuthMethod::JwtBearer, Some(Role::Billing)),
        claims(AuthMethod::ApiKey, None),
    ] {
        let _c = crate::auth::test_claims::Guard::set(who);
        let (s, _) = post_change(
            "198.51.100.7",
            json!({"action": "member.role_change", "target_id": "om_1"}),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _) = post_change(
            "198.51.100.7",
            json!({"action": "cmk.register", "target_id": "c"}),
        )
        .await;
        assert_eq!(s, StatusCode::FORBIDDEN);
    }
}

#[tokio::test]
async fn og35_og36_the_record_endpoint_obeys_the_ip_allowlist() {
    let _c = crate::auth::test_claims::Guard::set(admin());
    let _g = test_overrides::Guard::new(Some(Ok(access(&["203.0.113.0/24"], false))), None, None);
    let (s, body) = post_change(
        "198.51.100.7",
        json!({"action": "member.remove", "target_id": "om_1"}),
    )
    .await;
    assert_eq!(s, StatusCode::FORBIDDEN, "{body}");
    assert!(body.contains("admin_ip_not_allowed"));
}

// ── Reference table ────────────────────────────────────────────────────────────

#[test]
fn the_shipped_policy_parses_and_equals_the_fallback() {
    let parsed: ControlPolicy =
        serde_json::from_str(POLICY_JSON).expect("control_policy.v1.json parses");
    assert_eq!(parsed, ControlPolicy::fallback());
}

#[test]
fn locks_out_and_validate_allowlist_are_exact() {
    let list = vec!["203.0.113.0/24".to_owned()];
    assert!(locks_out(&list, Some("198.51.100.1".parse().unwrap())));
    assert!(!locks_out(&list, Some("203.0.113.200".parse().unwrap())));
    assert!(
        locks_out(&list, None),
        "an unprovable address is locked out"
    );
    assert!(!locks_out(&[], None), "no allowlist locks nobody out");
    assert_eq!(
        validate_allowlist(&[
            " 10.0.0.0/8 ".into(),
            "10.0.0.0/8".into(),
            "2001:db8::/48".into()
        ])
        .unwrap(),
        vec!["10.0.0.0/8".to_owned(), "2001:db8::/48".to_owned()]
    );
}

// ── rev5 M7: per-workspace rate limit on the admin plane ───────────────────────

fn admin_of(tenant: u128) -> Claims {
    Claims {
        tenant_id: TenantId::from_jwt_claim(Uuid::from_u128(tenant)),
        ..admin()
    }
}

/// rev5 M7: the control routes are rate-limited PER WORKSPACE (the cap is the reference
/// table's `rate_limit.control_routes_per_minute`; a test pins a small one). Past it the
/// gate answers 429 with `Retry-After`; another workspace is unaffected.
#[tokio::test]
async fn rev5_m7_control_routes_are_rate_limited_per_workspace() {
    let _g = test_overrides::Guard::new(Some(Ok(AdminAccess::default())), None, None);
    let _r = test_overrides::RateGuard::set(3, 100);
    let tenant = Uuid::new_v4().as_u128() >> 1;
    for i in 0..3 {
        let (s, body, _) = call(
            gate_router(
                admin_of(tenant),
                Capability::EditPolicies,
                Some("203.0.113.9"),
            ),
            &[],
        )
        .await;
        assert_eq!(s, StatusCode::NO_CONTENT, "call {i}: {body}");
    }
    let resp = gate_router(
        admin_of(tenant),
        Capability::EditPolicies,
        Some("203.0.113.9"),
    )
    .oneshot(
        Request::get("/probe")
            .header("authorization", format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(resp.headers().contains_key(header::RETRY_AFTER));
    let body =
        String::from_utf8(to_bytes(resp.into_body(), 1 << 16).await.unwrap().to_vec()).unwrap();
    assert!(body.contains("control_rate_limited"), "{body}");
    // Another workspace has its own bucket.
    let (s, _, _) = call(
        gate_router(
            admin_of(tenant + 1),
            Capability::EditPolicies,
            Some("203.0.113.9"),
        ),
        &[],
    )
    .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
}

/// rev5 M7: `POST /v1/audit/control-changes` writes to an undeletable table, so it has its
/// own, tighter per-workspace frequency cap and a cap on the whole change (before + after),
/// not only on each half.
#[tokio::test]
async fn rev5_m7_the_record_endpoint_caps_frequency_and_size() {
    let _g = test_overrides::Guard::new(Some(Ok(AdminAccess::default())), None, None);
    let _r = test_overrides::RateGuard::set(100, 2);
    let tenant = Uuid::new_v4().as_u128() >> 1;
    let _c = crate::auth::test_claims::Guard::set(admin_of(tenant));
    // rev6 N1: a non-incident action (member.remove has the incident bucket).
    let ok = json!({"action": "member.invite", "target_id": "om_1"});
    for _ in 0..2 {
        let (s, body) = post_change("198.51.100.7", ok.clone()).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "gate passed: {body}");
    }
    let (s, body) = post_change("198.51.100.7", ok).await;
    assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert!(body.contains("control_rate_limited"), "{body}");

    // Size: each half under its own cap, the whole over the change cap -> 413.
    let _c2 = crate::auth::test_claims::Guard::set(admin_of(tenant + 7));
    let half = policy().control_audit.change_json_max_bytes - 64;
    let big = "x".repeat(half);
    let (s, body) = post_change(
        "198.51.100.7",
        json!({"action": "member.remove", "target_id": "om_1",
               "before": {"v": big}, "after": {"v": big}}),
    )
    .await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
}

// ── rev6 N1: per-principal buckets; incident controls never locked out ─────────

fn principal(tenant: u128, sub: &str, method: AuthMethod, role: Option<Role>) -> Claims {
    Claims {
        tenant_id: TenantId::from_jwt_claim(Uuid::from_u128(tenant)),
        sub: sub.to_owned(),
        ..claims(method, role)
    }
}

async fn status_of(who: &Claims, gate: impl Into<ControlGate>, peer: &str) -> StatusCode {
    call(gate_router(who.clone(), gate, Some(peer)), &[])
        .await
        .0
}

/// rev6 N1 (ship-blocking): a developer and an admin-scoped API key each draining THEIR
/// admin-plane bucket cannot make the owner's pause / resume / revoke / revoke-all /
/// member removal — or even the owner's ordinary control calls — answer 429. RED before
/// the fix: one per-workspace bucket, so the owner's next call was 429.
#[tokio::test]
async fn rev6_n1_a_draining_principal_cannot_lock_the_owner_out() {
    let _g = test_overrides::Guard::new(Some(Ok(AdminAccess::default())), None, None);
    let _r = test_overrides::RateGuard::set4(3, 2, 1_000, 1_000);
    let tenant = Uuid::new_v4().as_u128() >> 1;
    let peer = "203.0.113.9";
    let developer = principal(
        tenant,
        "user_dev",
        AuthMethod::JwtBearer,
        Some(Role::Member),
    );
    let admin_key = principal(tenant, "apikey:1111", AuthMethod::ApiKey, None);
    let owner = principal(
        tenant,
        "user_owner",
        AuthMethod::JwtBearer,
        Some(Role::Owner),
    );

    // The developer (MintKeys: PATCH /v1/keys/{id}, POST /v1/keys) and the admin-scoped
    // key (EditBudgets: PUT /v1/billing/ceiling) drain their buckets to 429.
    for (who, cap) in [
        (&developer, Capability::MintKeys),
        (&admin_key, Capability::EditBudgets),
    ] {
        for i in 0..3 {
            assert_eq!(
                status_of(who, cap, peer).await,
                StatusCode::NO_CONTENT,
                "{} call {i}",
                who.sub
            );
        }
        assert_eq!(
            status_of(who, cap, peer).await,
            StatusCode::TOO_MANY_REQUESTS,
            "{} is throttled on its OWN bucket",
            who.sub
        );
    }

    // The owner is untouched: the incident controls and an ordinary control call.
    for gate in [
        incident(Capability::ManageControls), // pause / resume / blocks
        incident(Capability::ManageAllKeys),  // revoke-all / single-key revoke
        ControlGate::from(Capability::EditPolicies),
    ] {
        assert_eq!(
            status_of(&owner, gate, peer).await,
            StatusCode::NO_CONTENT,
            "the owner's {gate:?} must not be refused by another principal's spend"
        );
    }

    // Member removal through the dashboard's record endpoint (the audit record precedes
    // the WorkOS call): another admin drains THEIR web-change bucket; the owner's
    // `member.remove` still passes the gate (503 here = the gate passed; the dead pool
    // refuses the write).
    let other_admin = principal(
        tenant,
        "user_admin2",
        AuthMethod::JwtBearer,
        Some(Role::Owner),
    );
    {
        let _c = crate::auth::test_claims::Guard::set(other_admin.clone());
        for _ in 0..2 {
            let (s, body) = post_change(
                peer,
                json!({"action": "member.invite", "target_id": "om_1"}),
            )
            .await;
            assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "gate passed: {body}");
        }
        let (s, body) = post_change(
            peer,
            json!({"action": "member.invite", "target_id": "om_1"}),
        )
        .await;
        assert_eq!(s, StatusCode::TOO_MANY_REQUESTS, "{body}");
    }
    let _c = crate::auth::test_claims::Guard::set(owner.clone());
    for _ in 0..4 {
        let (s, body) = post_change(
            peer,
            json!({"action": "member.remove", "target_id": "om_9"}),
        )
        .await;
        assert_eq!(
            s,
            StatusCode::SERVICE_UNAVAILABLE,
            "the owner's member removal must pass the gate: {body}"
        );
    }
}

/// rev6 N1: the incident controls are exempt from the SHARED bucket — an owner who has
/// spent their own ordinary allowance can still pause, revoke and remove a member — and
/// draw on their own per-principal bucket, which is bounded.
#[tokio::test]
async fn rev6_n1_incident_controls_have_their_own_bucket() {
    let _g = test_overrides::Guard::new(Some(Ok(AdminAccess::default())), None, None);
    let _r = test_overrides::RateGuard::set4(2, 1, 1_000, 5);
    let tenant = Uuid::new_v4().as_u128() >> 1;
    let peer = "203.0.113.9";
    let owner = principal(
        tenant,
        "user_owner",
        AuthMethod::JwtBearer,
        Some(Role::Owner),
    );
    for _ in 0..2 {
        assert_eq!(
            status_of(&owner, Capability::EditPolicies, peer).await,
            StatusCode::NO_CONTENT
        );
    }
    assert_eq!(
        status_of(&owner, Capability::EditPolicies, peer).await,
        StatusCode::TOO_MANY_REQUESTS,
        "the owner's shared bucket is spent"
    );
    // The incident bucket is separate (5/min here).
    for i in 0..5 {
        let gate = if i % 2 == 0 {
            incident(Capability::ManageControls)
        } else {
            incident(Capability::ManageAllKeys)
        };
        assert_eq!(
            status_of(&owner, gate, peer).await,
            StatusCode::NO_CONTENT,
            "incident call {i}"
        );
    }
    assert_eq!(
        status_of(&owner, incident(Capability::ManageControls), peer).await,
        StatusCode::TOO_MANY_REQUESTS,
        "the incident bucket is generous, not unbounded"
    );
}

/// rev6 N1: the bucket is charged only AFTER the allowlist and SSO-required — the
/// owner's stolen credential used from outside the allowlist cannot spend the owner's
/// allowance (RED before the fix: charged before the allowlist, so the refused calls
/// emptied the owner's bucket).
#[tokio::test]
async fn rev6_n1_refused_calls_do_not_spend_the_principals_bucket() {
    let _g = test_overrides::Guard::new(Some(Ok(access(&["203.0.113.0/24"], false))), None, None);
    let _r = test_overrides::RateGuard::set4(2, 1_000, 1_000, 2);
    let tenant = Uuid::new_v4().as_u128() >> 1;
    let owner = principal(
        tenant,
        "user_owner",
        AuthMethod::JwtBearer,
        Some(Role::Owner),
    );
    for _ in 0..6 {
        assert_eq!(
            status_of(&owner, Capability::EditPolicies, "198.51.100.7").await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status_of(&owner, incident(Capability::ManageControls), "198.51.100.7").await,
            StatusCode::FORBIDDEN
        );
    }
    for _ in 0..2 {
        assert_eq!(
            status_of(&owner, Capability::EditPolicies, "203.0.113.9").await,
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            status_of(&owner, incident(Capability::ManageControls), "203.0.113.9").await,
            StatusCode::NO_CONTENT
        );
    }
}

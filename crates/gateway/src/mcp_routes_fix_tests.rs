use super::*;
use crate::auth::{
    AuthMethod, Role,
    capability::{CONTROL_ROUTES, Method as RegisteredMethod},
};
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use tower::ServiceExt;

#[tokio::test]
async fn mcp_control_runtime_capabilities_match_registry() {
    for route in CONTROL_ROUTES
        .iter()
        .filter(|r| r.path.starts_with("/v1/mcp-") || r.path.starts_with("/v1/approval"))
    {
        let method = match route.method {
            RegisteredMethod::Get => Method::GET,
            RegisteredMethod::Post => Method::POST,
            RegisteredMethod::Put => Method::PUT,
            RegisteredMethod::Patch => Method::PATCH,
            RegisteredMethod::Delete => Method::DELETE,
        };
        let path = route
            .path
            .replace("{id}", "00000000-0000-0000-0000-000000000040")
            .replace("{server_id}", "00000000-0000-0000-0000-000000000040")
            .replace("{tool_name}", "read");
        for role in [Role::Owner, Role::Member, Role::Viewer] {
            let mut claims = crate::auth::dev_stub_claims(AuthMethod::JwtBearer);
            claims.role = Some(role);
            claims.tenant_id = tracelane_shared::TenantId::from_jwt_claim(Uuid::new_v4());
            let allowed = claims.can(route.cap);
            let _auth = crate::auth::test_claims::Guard::set(claims);
            // Denied IP proves capability passed before any DB or mutation attempt.
            let _access = crate::control_plane::test_overrides::Guard::new(
                Some(Ok(crate::db::admin_security::AdminAccess {
                    admin_ip_allowlist: vec!["192.0.2.0/24".into()],
                    ..Default::default()
                })),
                None,
                None,
            );
            let state = crate::handler_harness::test_state(
                crate::providers::ProviderRegistry::new().unwrap(),
            );
            let response = router(state)
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri(&path)
                        .header("authorization", "Bearer fixture")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{method} {path}");
            let body: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(
                body["error"],
                if allowed {
                    "admin_ip_not_allowed"
                } else {
                    "role_forbidden"
                },
                "{method} {path} {role:?}: {body}"
            );
            if !allowed {
                assert_eq!(body["capability"], route.cap.slug(), "{method} {path}");
            }
        }
    }
}
#[tokio::test]
#[cfg(test)]
async fn mcp_unregistered_control_template_fails_closed() {
    let claims = crate::auth::dev_stub_claims(AuthMethod::JwtBearer);
    let _auth = crate::auth::test_claims::Guard::set(claims);
    let _access =
        crate::control_plane::test_overrides::Guard::new(Some(Ok(Default::default())), None, None);
    let state =
        crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
    let response = Router::new()
        .route("/v1/mcp-unregistered", get(control))
        .with_state(state)
        .oneshot(
            Request::builder()
                .uri("/v1/mcp-unregistered")
                .header("authorization", "Bearer fixture")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["error"], "role_forbidden");
}

#[tokio::test]
async fn denied_approval_endpoint_fails_closed_when_evidence_is_unavailable() {
    for auth_method in [AuthMethod::JwtBearer, AuthMethod::ApiKey] {
        for decision in ["approve", "deny"] {
            let mut claims = crate::auth::dev_stub_claims(auth_method);
            claims.role = Some(Role::Member);
            let _auth = crate::auth::test_claims::Guard::set(claims);
            let mut state = crate::handler_harness::test_state(
                crate::providers::ProviderRegistry::new().unwrap(),
            );
            let mut config = deadpool_postgres::Config::new();
            config.url = Some(
                "postgresql://synthetic:synthetic@127.0.0.1:1/synthetic?connect_timeout=1".into(),
            );
            state.pg = Some(
                config
                    .create_pool(
                        Some(deadpool_postgres::Runtime::Tokio1),
                        tokio_postgres::NoTls,
                    )
                    .unwrap(),
            );
            let response = router(state)
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/v1/approvals/{}/{decision}", Uuid::nil()))
                        .header("authorization", "Bearer fixture")
                        .body(Body::from("{}"))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "denial skipped evidence persistence"
            );
        }
    }
}

#[tokio::test]
async fn flag_off_denied_approval_preserves_403_with_unavailable_pool() {
    for auth_method in [AuthMethod::JwtBearer, AuthMethod::ApiKey] {
        for decision in ["approve", "deny"] {
            let mut claims = crate::auth::dev_stub_claims(auth_method);
            claims.role = Some(Role::Member);
            claims.tenant_id = tracelane_shared::TenantId::from_jwt_claim(Uuid::new_v4());
            let _auth = crate::auth::test_claims::Guard::set(claims.clone());
            let request = || {
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/approvals/{}/{decision}", Uuid::nil()))
                    .header("authorization", "Bearer fixture")
                    .body(Body::from("{}"))
                    .unwrap()
            };
            let state = crate::handler_harness::test_state(
                crate::providers::ProviderRegistry::new().unwrap(),
            );
            // Original denial, without the protected evidence store configured.
            let original = router(state.clone()).oneshot(request()).await.unwrap();
            assert_eq!(original.status(), StatusCode::FORBIDDEN);
            let original_body = to_bytes(original.into_body(), usize::MAX).await.unwrap();
            let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let resolver_calls = calls.clone();
            let cache = std::sync::Arc::new(crate::entitlement_cache::EntitlementCache::new(
                std::sync::Arc::new(move |_| {
                    assert_eq!(
                        resolver_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                        0,
                        "flag-off denial performed an entitlement lookup instead of using cache"
                    );
                    Box::pin(async {
                        Ok(crate::entitlement_cache::ResolvedEntitlements::deny_all())
                    })
                }),
            ));
            assert!(
                !cache
                    .resolved(*claims.tenant_id.as_uuid())
                    .await
                    .action_control
            );
            let mut state = state;
            state.entitlements = Some(cache);
            let mut config = deadpool_postgres::Config::new();
            config.url = Some("postgresql://synthetic:synthetic@127.0.0.1:1/synthetic".into());
            let pool = config
                .create_pool(
                    Some(deadpool_postgres::Runtime::Tokio1),
                    tokio_postgres::NoTls,
                )
                .unwrap();
            pool.close();
            state.pg = Some(pool);
            let response = router(state).oneshot(request()).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "flag OFF and unavailable pool changed the original denial"
            );
            assert_eq!(
                to_bytes(response.into_body(), usize::MAX).await.unwrap(),
                original_body,
                "flag OFF changed the original 403 body"
            );
            assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        }
    }
}

#[tokio::test]
async fn flag_off_does_not_bypass_granting_path_store_failure() {
    let claims = crate::auth::dev_stub_claims(AuthMethod::JwtBearer);
    let _auth = crate::auth::test_claims::Guard::set(claims.clone());
    let _access =
        crate::control_plane::test_overrides::Guard::new(Some(Ok(Default::default())), None, None);
    let mut state =
        crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
    let cache = std::sync::Arc::new(crate::entitlement_cache::EntitlementCache::new(
        std::sync::Arc::new(|_| {
            Box::pin(async { Ok(crate::entitlement_cache::ResolvedEntitlements::deny_all()) })
        }),
    ));
    cache.resolved(*claims.tenant_id.as_uuid()).await;
    state.entitlements = Some(cache);
    let mut config = deadpool_postgres::Config::new();
    config.url = Some("postgresql://synthetic:synthetic@127.0.0.1:1/synthetic".into());
    let pool = config
        .create_pool(
            Some(deadpool_postgres::Runtime::Tokio1),
            tokio_postgres::NoTls,
        )
        .unwrap();
    pool.close();
    state.pg = Some(pool);
    let response = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/approvals/{}/approve", Uuid::nil()))
                .header("authorization", "Bearer fixture")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["error"], "mcp_store_unavailable");
}

#[tokio::test]
async fn invalidated_flag_off_cache_cannot_skip_rejection_evidence() {
    let mut claims = crate::auth::dev_stub_claims(AuthMethod::JwtBearer);
    claims.role = Some(Role::Member);
    let _auth = crate::auth::test_claims::Guard::set(claims.clone());
    let cache = std::sync::Arc::new(crate::entitlement_cache::EntitlementCache::new(
        std::sync::Arc::new(|_| {
            Box::pin(async { Ok(crate::entitlement_cache::ResolvedEntitlements::deny_all()) })
        }),
    ));
    cache.resolved(*claims.tenant_id.as_uuid()).await;
    cache.invalidate(*claims.tenant_id.as_uuid()).await;
    let mut state =
        crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
    state.entitlements = Some(cache);
    let mut config = deadpool_postgres::Config::new();
    config.url = Some("postgresql://synthetic:synthetic@127.0.0.1:1/synthetic".into());
    let pool = config
        .create_pool(
            Some(deadpool_postgres::Runtime::Tokio1),
            tokio_postgres::NoTls,
        )
        .unwrap();
    pool.close();
    state.pg = Some(pool);
    let response = router(state)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/approvals/{}/approve", Uuid::nil()))
                .header("authorization", "Bearer fixture")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}

fn fix_pass_closed_pool() -> deadpool_postgres::Pool {
    let mut config = deadpool_postgres::Config::new();
    config.url = Some("postgresql://synthetic:synthetic@127.0.0.1:1/synthetic".into());
    let pool = config
        .create_pool(
            Some(deadpool_postgres::Runtime::Tokio1),
            tokio_postgres::NoTls,
        )
        .unwrap();
    pool.close();
    pool
}
#[tokio::test]
async fn fix_pass_non_role_refusals_never_acquire_evidence_connection() {
    for kind in ["ip", "sso", "rate"] {
        let mut claims = crate::auth::dev_stub_claims(AuthMethod::JwtBearer);
        claims.role = Some(Role::Owner);
        claims.tenant_id = tracelane_shared::TenantId::from_jwt_claim(Uuid::new_v4());
        let _auth = crate::auth::test_claims::Guard::set(claims.clone());
        let access = crate::db::admin_security::AdminAccess {
            admin_ip_allowlist: if kind == "ip" {
                vec!["192.0.2.0/24".into()]
            } else {
                vec![]
            },
            sso_required: kind == "sso",
            ..Default::default()
        };
        let _access = crate::control_plane::test_overrides::Guard::new(
            Some(Ok(access)),
            Some(Ok(false)),
            None,
        );
        let _rate = crate::control_plane::test_overrides::RateGuard::set(1, 100);
        if kind == "rate" {
            crate::control_plane::require_control(
                &claims,
                crate::auth::capability::Capability::ApproveToolCalls,
                &HeaderMap::new(),
            )
            .await
            .unwrap();
        }
        let mut state =
            crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
        state.pg = Some(fix_pass_closed_pool());
        let response = router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/approvals/{}/approve", Uuid::nil()))
                    .header("authorization", "Bearer fixture")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if kind == "rate" {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::FORBIDDEN
            },
            "{kind} refusal attempted SQL"
        );
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                .unwrap();
        assert_eq!(
            body["error"],
            match kind {
                "ip" => "admin_ip_not_allowed",
                "sso" => "sso_required",
                _ => "control_rate_limited",
            }
        );
    }
}
#[tokio::test]
async fn fix_pass_role_refusals_exhaust_budget_before_pool_acquisition() {
    let mut claims = crate::auth::dev_stub_claims(AuthMethod::JwtBearer);
    claims.role = Some(Role::Member);
    claims.tenant_id = tracelane_shared::TenantId::from_jwt_claim(Uuid::new_v4());
    let _auth = crate::auth::test_claims::Guard::set(claims);
    let _rate = crate::control_plane::test_overrides::RateGuard::set(2, 100);
    let mut state =
        crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
    state.pg = Some(fix_pass_closed_pool());
    for attempt in 0..3 {
        let response = router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/v1/approvals/{}/deny", Uuid::nil()))
                    .header("authorization", "Bearer fixture")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if attempt < 2 {
                StatusCode::SERVICE_UNAVAILABLE
            } else {
                StatusCode::FORBIDDEN
            },
            "attempt {attempt}: refusal evidence budget not applied before SQL"
        );
    }
}
#[tokio::test]
async fn fix_pass_flag_off_authorized_decision_skips_protected_probe() {
    let claims = crate::auth::dev_stub_claims(AuthMethod::JwtBearer);
    let mut state =
        crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
    let cache = std::sync::Arc::new(crate::entitlement_cache::EntitlementCache::new(
        std::sync::Arc::new(|_| {
            Box::pin(async { Ok(crate::entitlement_cache::ResolvedEntitlements::deny_all()) })
        }),
    ));
    cache.resolved(*claims.tenant_id.as_uuid()).await;
    state.entitlements = Some(cache);
    state.pg = Some(fix_pass_closed_pool());
    for decision in [true, false] {
        assert!(
            matches!(
                protected_decision(
                    &state,
                    &claims,
                    &HeaderMap::new(),
                    Uuid::nil(),
                    Some(decision),
                    "",
                    None,
                    None
                )
                .await,
                Ok(None)
            ),
            "flag OFF acquired connection for protected-only probe"
        );
    }
}

use super::*;
use crate::{
    auth::{AuthMethod, Role},
    handler_harness::test_state,
    providers::ProviderRegistry,
};
use axum::{
    body::{Body, to_bytes},
    http::Request,
};
use tower::ServiceExt;

async fn get(
    path: &str,
    role: Role,
    access: Result<crate::db::admin_security::AdminAccess, ()>,
) -> (StatusCode, serde_json::Value) {
    let mut claims = crate::auth::dev_stub_claims(AuthMethod::JwtBearer);
    claims.tenant_id = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::new_v4());
    claims.role = Some(role);
    let _auth = crate::auth::test_claims::Guard::set(claims);
    let _control =
        crate::control_plane::test_overrides::Guard::new(Some(access), Some(Ok(false)), None);
    let state = test_state(ProviderRegistry::new().unwrap());
    let app = router(state.clone()).merge(crate::mcp_routes::router(state));
    let response = app
        .oneshot(
            Request::builder()
                .uri(path)
                .header("authorization", "Bearer fixture")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, serde_json::from_slice(&body).unwrap())
}
#[tokio::test]
async fn og38_data_controls_get_enforces_control_boundary() {
    let cases = [
        (
            Ok(crate::db::admin_security::AdminAccess {
                admin_ip_allowlist: vec!["192.0.2.0/24".into()],
                ..Default::default()
            }),
            StatusCode::FORBIDDEN,
            "admin_ip_not_allowed",
        ),
        (
            Ok(crate::db::admin_security::AdminAccess {
                sso_required: true,
                ..Default::default()
            }),
            StatusCode::FORBIDDEN,
            "sso_required",
        ),
        (
            Err(()),
            StatusCode::SERVICE_UNAVAILABLE,
            "control_settings_unavailable",
        ),
    ];
    for (access, expected, code) in cases {
        let (status, body) = get("/v1/data-controls", Role::Owner, access).await;
        assert_eq!(status, expected, "{body}");
        assert_eq!(body["error"], code, "{body}");
        assert!(body.get("keys").is_none());
    }
}
#[tokio::test]
async fn viewer_cannot_read_mcp_server_controls() {
    for path in [
        "/v1/mcp-servers",
        "/v1/mcp-servers/00000000-0000-0000-0000-000000000040",
    ] {
        let (status, body) = get(path, Role::Viewer, Ok(Default::default())).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
        assert_eq!(body["error"], "role_forbidden");
        for field in ["url", "credential_header", "credential_last4", "servers"] {
            assert!(body.get(field).is_none());
        }
    }
}
#[tokio::test]
#[ignore = "disposable Postgres"]
async fn og38_viewer_data_controls_contains_no_secrets() {
    let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
    crate::entitlement_cache::b409_fixture::seed_v3_then_v4(&pool).await;
    let tenant = crate::entitlement_cache::b409_fixture::builder_tenant(&pool, None, None).await;
    let sibling = crate::entitlement_cache::b409_fixture::builder_tenant(&pool, None, None).await;
    let key_id = uuid::Uuid::new_v4();
    let pg = pool.get().await.unwrap();
    pg.execute("INSERT INTO api_keys(id,tenant_id,name,key_hash,key_prefix,capture) VALUES($1,$2,'Viewer key','HASH_SECRET_SENTINEL','tlane_safe',$3)", &[&key_id,&tenant,&json!({"input":false})]).await.unwrap();
    pg.execute("INSERT INTO api_keys(tenant_id,name,key_hash,key_prefix) VALUES($1,'SIBLING_SENTINEL','SIBLING_HASH_SECRET','tlane_other')", &[&sibling]).await.unwrap();
    drop(pg);
    let mut claims = crate::auth::dev_stub_claims(AuthMethod::JwtBearer);
    claims.tenant_id = tracelane_shared::TenantId::from_jwt_claim(tenant);
    claims.role = Some(Role::Viewer);
    let _auth = crate::auth::test_claims::Guard::set(claims);
    let _control =
        crate::control_plane::test_overrides::Guard::new(Some(Ok(Default::default())), None, None);
    let mut state = test_state(ProviderRegistry::new().unwrap());
    state.pg = Some(pool);
    let response = router(state)
        .oneshot(
            Request::builder()
                .uri("/v1/data-controls")
                .header("authorization", "Bearer fixture")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body: Value =
        serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap()).unwrap();
    assert_eq!(body["can_edit"], false);
    assert!(body["retention"]["effective_days"].as_i64().unwrap() > 0);
    assert_eq!(
        body["keys"],
        json!([{"id":key_id.to_string(),"name":"Viewer key","prefix":"tlane_safe","capture":{"input":false}}])
    );
    let serialized = body.to_string();
    for forbidden in [
        "HASH_SECRET_SENTINEL",
        "SIBLING_SENTINEL",
        "SIBLING_HASH_SECRET",
        "key_hash",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "private key field leaked: {forbidden}"
        );
    }
    for forbidden in ["credential", "key_hash", "url", "token", "secret"] {
        assert!(
            !body
                .as_object()
                .unwrap()
                .keys()
                .any(|key| key.contains(forbidden))
        );
    }
}

#[tokio::test]
#[ignore = "disposable Postgres"]
async fn og38_server_retention_decrease_requires_exact_confirmation() {
    let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
    crate::entitlement_cache::b409_fixture::seed_v3_then_v4(&pool).await;
    let tenant = crate::entitlement_cache::b409_fixture::builder_tenant(&pool, None, None).await;
    let mut claims = crate::auth::dev_stub_claims(AuthMethod::JwtBearer);
    claims.tenant_id = tracelane_shared::TenantId::from_jwt_claim(tenant);
    let actor = crate::control_plane::ControlActor::for_test(claims.tenant_id.clone());
    let policy = crate::db::data_controls::Policy::embedded().unwrap();
    for confirm in [None, Some("delete data older than 91 days")] {
        let body = RetentionBody {
            days: Some(90),
            confirm: confirm.map(str::to_owned),
        };
        let err = save_retention(&pool, &claims, &actor, &body, policy)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "confirmation_required");
        assert_eq!(
            pool.get()
                .await
                .unwrap()
                .query_one(
                    "SELECT count(*) FROM workspace_data_controls WHERE tenant_id=$1",
                    &[&tenant]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            0
        );
    }
    let body = RetentionBody {
        days: Some(90),
        confirm: Some("delete data older than 90 days".into()),
    };
    assert!(
        save_retention(&pool, &claims, &actor, &body, policy)
            .await
            .unwrap()
    );
    assert_eq!(
        pool.get()
            .await
            .unwrap()
            .query_one(
                "SELECT retention_days FROM workspace_data_controls WHERE tenant_id=$1",
                &[&tenant]
            )
            .await
            .unwrap()
            .get::<_, i32>(0),
        90
    );
}

#[tokio::test]
#[ignore = "disposable Postgres"]
async fn og38_migrations_0078_to_0081_are_reapplicable() {
    let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
    let client = pool.get().await.unwrap();
    for (name, sql) in [
        (
            "0078",
            include_str!("../../../apps/web/db/migrations/0078_og38_data_controls.sql"),
        ),
        (
            "0079",
            include_str!("../../../apps/web/db/migrations/0079_og40_mcp_servers.sql"),
        ),
        (
            "0080",
            include_str!("../../../apps/web/db/migrations/0080_og41_mcp_policy.sql"),
        ),
        (
            "0081",
            include_str!("../../../apps/web/db/migrations/0081_og42_approvals.sql"),
        ),
        (
            "0082",
            include_str!("../../../apps/web/db/migrations/0082_og42_active_approvals.sql"),
        ),
    ] {
        for attempt in 1..=2 {
            client
                .batch_execute(sql)
                .await
                .unwrap_or_else(|error| panic!("{name} reapply {attempt}: {error}"));
        }
    }
    assert_eq!(client.query_one("SELECT count(*) FROM pg_constraint WHERE conrelid='api_keys'::regclass AND conname='api_keys_capture_object'",&[]).await.unwrap().get::<_,i64>(0),1);
}

#[tokio::test]
#[ignore = "disposable Postgres"]
async fn retention_put_does_not_wait_for_sweep() {
    let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
    crate::entitlement_cache::b409_fixture::seed_v3_then_v4(&pool).await;
    let tenant = crate::entitlement_cache::b409_fixture::builder_tenant(&pool, None, None).await;
    let mut claims = crate::auth::dev_stub_claims(AuthMethod::JwtBearer);
    claims.tenant_id = tracelane_shared::TenantId::from_jwt_claim(tenant);
    let actor = crate::control_plane::ControlActor::for_test(claims.tenant_id.clone());
    let policy = crate::db::data_controls::Policy::embedded().unwrap();
    let body = RetentionBody {
        days: Some(180),
        confirm: Some("delete data older than 180 days".into()),
    };
    let mut locker = pool.get().await.unwrap();
    let tx = locker.transaction().await.unwrap();
    let key = crate::retention_sweep::retention_lock_key(&tx, &tenant.to_string())
        .await
        .unwrap();
    tx.query_one("SELECT pg_advisory_xact_lock_shared($1)", &[&key])
        .await
        .unwrap();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        save_retention(&pool, &claims, &actor, &body, policy),
    )
    .await;
    assert!(
        result.is_ok(),
        "retention PUT must refuse promptly behind a sweep, not wait for its lock"
    );
    assert!(result.unwrap().is_err());
    let counts = tx.query_one("SELECT (SELECT count(*) FROM workspace_data_controls WHERE tenant_id=$1), (SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id=$1)", &[&tenant]).await.unwrap();
    assert_eq!(counts.get::<_, i64>(0), 0);
    assert_eq!(counts.get::<_, i64>(1), 0);
    tx.rollback().await.unwrap();
    assert!(
        save_retention(&pool, &claims, &actor, &body, policy)
            .await
            .unwrap()
    );
}

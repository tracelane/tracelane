//! `OG-35` / `OG-36` against REAL Postgres (`#[ignore]`d; run by
//! `scripts/ci/run-postgres-integration.sh`, filter `control_plane::pg_tests`). Each test
//! takes a fresh database migrated with every file `apply_migrations` lists (0058/0059
//! included).

use axum::{
    body::{Body, to_bytes},
    extract::connect_info::MockConnectInfo,
    http::{Request, StatusCode},
};
use serde_json::json;
use tower::ServiceExt as _;
use tracelane_shared::TenantId;

use crate::auth::scope::KeyScope;
use crate::auth::{AuthMethod, Claims, Role};
use crate::db::admin_security::{self, AdminAccess};
use crate::db::control_audit::{self, Actor, Change, ListQuery};
use crate::entitlement_cache::b409_fixture::fresh_migrated_pool;

async fn tenant(c: &deadpool_postgres::Client, label: &str) -> TenantId {
    let org = format!("org_og35_{label}_{}", uuid::Uuid::new_v4().simple());
    let id: uuid::Uuid = c
        .query_one(
            "INSERT INTO tenants (workos_org_id, name) VALUES ($1, $2) RETURNING id",
            &[&org, &label],
        )
        .await
        .expect("insert tenant")
        .get(0);
    TenantId::from_jwt_claim(id)
}

fn change<'a>(action: &'a str, target: &str) -> Change<'a> {
    Change {
        action,
        target_type: "test",
        target_id: target.to_owned(),
        before: Some(json!({"v": 1})),
        after: Some(json!({"v": 2, "rawKey": "never-stored"})),
    }
}

#[tokio::test]
#[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
async fn og36_pg_admin_access_put_records_before_after_and_refuses_when_the_audit_row_is_refused() {
    let pool = fresh_migrated_pool().await;
    let c = pool.get().await.unwrap();
    let t = tenant(&c, "access").await;
    let actor = Actor {
        sub: "user_admin".into(),
        role: "admin",
        auth_method: "workos_session",
        request_id: uuid::Uuid::new_v4().to_string(),
        ip: Some("203.0.113.9".parse().unwrap()),
        user_agent: Some("og36-test".into()),
    };
    let (before, after) = admin_security::put(&pool, &t, &["203.0.113.0/24".into()], true, &actor)
        .await
        .expect("audited put");
    assert_eq!(before, AdminAccess::default());
    assert_eq!(after.admin_ip_allowlist, vec!["203.0.113.0/24".to_owned()]);
    assert!(after.sso_required);
    let row = c
        .query_one(
            "SELECT actor_user_id, actor_role, actor_auth_method, request_id, host(ip_addr),
                    before_json, after_json
               FROM admin_audit_log WHERE actor_workspace_id = $1 AND action = 'security.admin_access.set'",
            &[t.as_uuid()],
        )
        .await
        .expect("exactly one audit row");
    assert_eq!(row.get::<_, String>(0), "user_admin");
    assert_eq!(row.get::<_, Option<String>>(1).as_deref(), Some("admin"));
    assert_eq!(
        row.get::<_, Option<String>>(2).as_deref(),
        Some("workos_session")
    );
    assert_eq!(
        row.get::<_, Option<String>>(3),
        Some(actor.request_id.clone())
    );
    assert_eq!(
        row.get::<_, Option<String>>(4).as_deref(),
        Some("203.0.113.9")
    );
    assert_eq!(
        row.get::<_, serde_json::Value>(5),
        json!({"admin_ip_allowlist": [], "sso_required": false})
    );
    assert_eq!(
        row.get::<_, serde_json::Value>(6),
        json!({"admin_ip_allowlist": ["203.0.113.0/24"], "sso_required": true})
    );

    // Fail-CLOSED: the audit insert is refused → the policy change is rolled back.
    c.batch_execute(
        "ALTER TABLE admin_audit_log ADD CONSTRAINT og36_refusal CHECK (action <> 'security.admin_access.set') NOT VALID",
    )
    .await
    .unwrap();
    assert!(
        admin_security::put(&pool, &t, &[], false, &actor)
            .await
            .is_err(),
        "a refused audit row must refuse the change"
    );
    let stored = admin_security::get(&pool, &t).await.unwrap();
    assert_eq!(
        (stored.admin_ip_allowlist, stored.sso_required),
        (vec!["203.0.113.0/24".to_owned()], true),
        "nothing changed"
    );
}

#[tokio::test]
#[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
async fn og35_pg_the_trail_is_append_only_except_for_a_tombstoned_purge() {
    let pool = fresh_migrated_pool().await;
    let c = pool.get().await.unwrap();
    let t = tenant(&c, "append").await;
    let id = control_audit::record_standalone(&pool, &t, &Actor::system("u"), change("x.set", "a"))
        .await
        .unwrap();
    let stored: serde_json::Value = c
        .query_one(
            "SELECT after_json FROM admin_audit_log WHERE id = $1",
            &[&id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        stored["rawKey"],
        control_audit::REDACTED,
        "redacted before storage"
    );
    for (what, sql) in [
        (
            "update",
            "UPDATE admin_audit_log SET action = 'forged' WHERE id = $1",
        ),
        ("delete", "DELETE FROM admin_audit_log WHERE id = $1"),
    ] {
        let err = c.execute(sql, &[&id]).await.expect_err(what);
        assert!(
            format!("{err:?}").contains("append-only"),
            "{what}: {err:?}"
        );
    }
    assert!(
        c.batch_execute("TRUNCATE admin_audit_log").await.is_err(),
        "truncate refused"
    );
    c.execute(
        "INSERT INTO purged_tenants (tenant_id, purged_by) VALUES ($1, 'og35-test')",
        &[t.as_uuid()],
    )
    .await
    .unwrap();
    assert_eq!(
        c.execute("DELETE FROM admin_audit_log WHERE id = $1", &[&id])
            .await
            .unwrap(),
        1,
        "the GDPR purge of a tombstoned workspace still erases"
    );
}

#[tokio::test]
#[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
async fn og35_pg_the_trail_is_tenant_scoped_and_pages_by_cursor() {
    let pool = fresh_migrated_pool().await;
    let c = pool.get().await.unwrap();
    let a = tenant(&c, "a").await;
    let b = tenant(&c, "b").await;
    for i in 0..3 {
        control_audit::record_standalone(
            &pool,
            &a,
            &Actor::system("ua"),
            change("a.set", &i.to_string()),
        )
        .await
        .unwrap();
    }
    control_audit::record_standalone(&pool, &b, &Actor::system("ub"), change("b.set", "x"))
        .await
        .unwrap();
    let q = |before_id| ListQuery {
        limit: 2,
        before_id,
        ..ListQuery::default()
    };
    let p1 = control_audit::list(&pool, &a, &q(None)).await.unwrap();
    assert_eq!(p1.len(), 2);
    assert!(p1[0].id > p1[1].id, "newest first");
    let p2 = control_audit::list(&pool, &a, &q(Some(p1[1].id)))
        .await
        .unwrap();
    assert_eq!(p2.len(), 1);
    let all: Vec<_> = p1.iter().chain(&p2).collect();
    assert!(
        all.iter().all(|r| r.action == "a.set"),
        "tenant B's row never appears"
    );
    assert_eq!(
        control_audit::list(&pool, &b, &q(None))
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
#[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
async fn og36_pg_the_table_refuses_a_non_cidr_allowlist_entry() {
    let pool = fresh_migrated_pool().await;
    let c = pool.get().await.unwrap();
    let t = tenant(&c, "cidr").await;
    for bad in ["not-a-cidr", "10.0.0.1/8"] {
        let r = c
            .execute(
                "INSERT INTO tenant_admin_security (tenant_id, admin_ip_allowlist) VALUES ($1, $2)",
                &[t.as_uuid(), &vec![bad.to_owned()]],
            )
            .await;
        assert!(r.is_err(), "{bad} must be refused by the CHECK");
    }
}

/// The route end to end on real Postgres: an admin's PUT through the REAL router and
/// the REAL B-594 layer writes the policy and an audit row carrying the request
/// context; a developer's PUT writes nothing.
#[tokio::test]
#[ignore = "needs POSTGRES_TEST_URL — run scripts/ci/run-postgres-integration.sh"]
async fn og36_pg_the_route_writes_the_policy_and_its_audit_row_for_an_admin_only() {
    let pool = fresh_migrated_pool().await;
    let c = pool.get().await.unwrap();
    let t = tenant(&c, "route").await;
    let app = || {
        super::router(pool.clone())
            .layer(axum::middleware::from_fn_with_state(
                crate::preauth_limiter::PreAuthLimiter::new(60),
                crate::preauth_limiter::layer,
            ))
            .layer(MockConnectInfo(std::net::SocketAddr::new(
                "203.0.113.7".parse().unwrap(),
                4000,
            )))
    };
    let put = |body: serde_json::Value| {
        Request::put("/v1/security/admin-access")
            .header("authorization", "Bearer test-token-not-a-real-jwt")
            .header("content-type", "application/json")
            .header("user-agent", "og36-route-test")
            .body(Body::from(body.to_string()))
            .unwrap()
    };
    // The policy READ goes to the override (the global pool is process-wide); the
    // WRITE goes through the route's own pool — the real table and the real trigger.
    let _g = super::test_overrides::Guard::new(Some(Ok(AdminAccess::default())), None, None);
    let who = |role| Claims {
        tenant_id: t.clone(),
        sub: "user_route".into(),
        auth_method: AuthMethod::JwtBearer,
        role: Some(role),
        key_scope: KeyScope::LegacyFullSurface,
        budget_usd_monthly: None,
        rate_limit_rpm: None,
        budget_reset: crate::spend::BudgetReset::Monthly,
        governance: None,
    };
    {
        let _c = crate::auth::test_claims::Guard::set(who(Role::Member));
        let resp = app()
            .oneshot(put(json!({"admin_ip_allowlist": ["203.0.113.0/24"]})))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
    let _c = crate::auth::test_claims::Guard::set(who(Role::Owner));
    let resp = app()
        .oneshot(put(json!({"admin_ip_allowlist": ["203.0.113.0/24"]})))
        .await
        .unwrap();
    let status = resp.status();
    let body =
        String::from_utf8(to_bytes(resp.into_body(), 1 << 16).await.unwrap().to_vec()).unwrap();
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains("\"your_ip\":\"203.0.113.7\""), "{body}");
    let n: i64 = c
        .query_one(
            "SELECT count(*) FROM admin_audit_log
              WHERE actor_workspace_id = $1 AND action = 'security.admin_access.set'
                AND actor_role = 'admin' AND user_agent = 'og36-route-test'
                AND host(ip_addr) = '203.0.113.7' AND request_id IS NOT NULL",
            &[t.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        n, 1,
        "exactly one audit row, from the admin, with the request context"
    );
}

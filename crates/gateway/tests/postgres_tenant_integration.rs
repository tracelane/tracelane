//! Live Postgres integration tests for Move #1 — tenant + api_key flow.
//!
//! Default: `#[ignore]`. Run with a live Postgres available:
//!
//!   POSTGRES_TEST_URL=postgres://tracelane:tracelane_dev@localhost:5432/tracelane \
//!   cargo test --test postgres_tenant_integration -- --ignored --nocapture
//!
//! Always-on: a smoke test that just imports the module surface and
//! asserts the `peppered_lookup` deterministic-32-byte contract — catches
//! refactor breakage even when the founder hasn't booted Postgres.
//!
//! Tenant isolation: each test fabricates a fresh UUID-derived tenant_id
//! so concurrent runs and dirty databases don't collide.

#![allow(dead_code)]

use anyhow::Result;
use uuid::Uuid;

// Pull in the gateway-internal modules under test via the same #[path]
// trick used by clickhouse_persister_integration.rs. Works here because
// db::api_keys + db::tenants don't reach for crate::predictive or
// other gateway-internal paths.
#[path = "../src/db/mod.rs"]
#[allow(dead_code)]
mod db;
// B-383 (a): the KEK ring and the rotate command, for the real-Postgres re-wrap
// proof below. `byok_rotate` reaches `crate::byok` and `crate::db`, which is why
// both are mounted here under those exact names.
#[path = "../src/byok.rs"]
#[allow(dead_code)]
mod byok;
#[path = "../src/byok_rotate.rs"]
#[allow(dead_code)]
mod byok_rotate;

fn url() -> Option<String> {
    std::env::var("POSTGRES_TEST_URL").ok()
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn scheduled_key_early_revoke_notifies_again() -> Result<()> {
    use db::api_keys::*;
    let pool = test_pool().await?;
    let tenant_id = Uuid::new_v4();
    db::tenants::create(&pool, tenant_id, "revoke-grace-test", "free").await?;
    let tenant = tracelane_shared::TenantId::from_jwt_claim(tenant_id);
    let _ = init_pepper(&"11".repeat(32));
    let key = mint(
        &pool,
        &tenant,
        "early-retirement",
        None,
        MintOptions::default(),
    )
    .await?;
    let client = pool.get().await?;
    let database: String = client
        .query_one("SELECT current_database()", &[])
        .await?
        .get(0);
    let mut config: tokio_postgres::Config = require_url().parse()?;
    config.dbname(&database);
    let (listener, mut connection) = config.connect(tokio_postgres::NoTls).await?;
    let (send, mut receive) = tokio::sync::mpsc::unbounded_channel();
    let pump = tokio::spawn(async move {
        while let Some(message) = futures::future::poll_fn(|cx| connection.poll_message(cx)).await {
            if let Ok(tokio_postgres::AsyncMessage::Notification(n)) = message {
                let _ = send.send((n.channel().to_owned(), n.payload().to_owned()));
            }
        }
    });
    listener
        .batch_execute("LISTEN key_revoked; LISTEN test_barrier")
        .await?;
    client
        .execute(
            "UPDATE api_keys SET revoked_at = now() + interval '1 hour' WHERE id = $1",
            &[&key.api_key.id],
        )
        .await?;
    let first = tokio::time::timeout(std::time::Duration::from_secs(10), receive.recv())
        .await?
        .unwrap();
    assert_eq!(first.0, "key_revoked");
    revoke(&pool, key.api_key.id).await?;
    let revoked: bool = client
        .query_one(
            "SELECT revoked_at <= now() FROM api_keys WHERE id = $1",
            &[&key.api_key.id],
        )
        .await?
        .get(0);
    assert!(
        revoked,
        "explicit revoke must end a scheduled key's grace now"
    );
    client.batch_execute("NOTIFY test_barrier").await?;
    let next = tokio::time::timeout(std::time::Duration::from_secs(10), receive.recv())
        .await?
        .unwrap();
    assert_eq!(
        next, first,
        "early retirement must emit a second cache invalidation before the barrier"
    );
    assert_eq!(receive.recv().await.unwrap().0, "test_barrier");
    revoke(&pool, key.api_key.id).await?;
    client.batch_execute("NOTIFY test_barrier").await?;
    assert_eq!(
        receive.recv().await.unwrap().0,
        "test_barrier",
        "repeated revoke is a no-op"
    );
    pump.abort();
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn provider_validation_records_only_current_tenant_key_version() -> Result<()> {
    use db::provider_keys::*;
    let pool = test_pool().await?;
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    db::tenants::create(&pool, a, "provider-validation-a", "free").await?;
    db::tenants::create(&pool, b, "provider-validation-b", "free").await?;
    let a = tracelane_shared::TenantId::from_jwt_claim(a);
    let b = tracelane_shared::TenantId::from_jwt_claim(b);
    upsert(
        &pool,
        &a,
        "anthropic",
        "default",
        "unit-test-ciphertext-only",
        "test",
        &db::control_audit::Actor::system("owner-a"),
    )
    .await?;
    let source = get(&pool, &a, "anthropic", "default").await?.unwrap();
    assert!(source.saved_at <= chrono::Utc::now());
    assert!(source.last_validation.is_none());
    assert!(get(&pool, &b, "anthropic", "default").await?.is_none());
    let result = KeyValidation {
        status: "valid".into(),
        reason: "authenticated".into(),
        checked_at: chrono::Utc::now(),
    };
    assert!(
        !record_validation(
            &pool,
            &b,
            &source,
            &db::control_audit::Actor::system("other-owner"),
            &result
        )
        .await?
    );
    assert!(
        record_validation(
            &pool,
            &a,
            &source,
            &db::control_audit::Actor::system("owner-a"),
            &result
        )
        .await?
    );
    let rows = list(&pool, &a).await?;
    assert_eq!(rows[0].last_validation.as_ref().unwrap().status, "valid");
    assert_eq!(
        rows[0].last_validation.as_ref().unwrap().checked_at,
        result.checked_at
    );
    assert!(list(&pool, &b).await?.is_empty());
    // Replacing the key updates saved_at and invalidates prior validation results.
    upsert(
        &pool,
        &a,
        "anthropic",
        "default",
        "unit-test-replacement-ciphertext",
        "next",
        &db::control_audit::Actor::system("owner-a"),
    )
    .await?;
    assert!(list(&pool, &a).await?[0].last_validation.is_none());
    assert!(
        !record_validation(
            &pool,
            &a,
            &source,
            &db::control_audit::Actor::system("owner-a"),
            &result
        )
        .await?
    );
    let client = pool.get().await?;
    let audit = client.query_one("SELECT actor_user_id, after_json::text FROM admin_audit_log WHERE actor_workspace_id = $1 AND action = 'provider_key.validate'", &[a.as_uuid()]).await?;
    assert_eq!(audit.get::<_, &str>(0), "owner-a");
    assert!(!audit.get::<_, &str>(1).contains("ciphertext"));
    delete(
        &pool,
        &a,
        "anthropic",
        "default",
        &db::control_audit::Actor::system("owner-a"),
    )
    .await?;
    assert!(
        !record_validation(
            &pool,
            &a,
            &source,
            &db::control_audit::Actor::system("owner-a"),
            &result
        )
        .await?
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn rotation_preserves_settings_authenticates_grace_and_audits() -> Result<()> {
    use db::api_keys::*;
    let pool = test_pool().await?;
    let tenant_id = Uuid::new_v4();
    db::tenants::create(&pool, tenant_id, "rotation-test", "free").await?;
    let tenant = tracelane_shared::TenantId::from_jwt_claim(tenant_id);
    let _ = init_pepper(&"11".repeat(32));
    let options = MintOptions {
        scope: Some(vec!["read".into()]),
        expires_at: Some(chrono::Utc::now() + chrono::Duration::days(7)),
        budget_usd_monthly: Some(12.3456),
        rate_limit_rpm: Some(17),
        budget_reset: Some(tracelane_shared::spend::BudgetReset::Weekly),
        velocity_breaker: true,
        ..Default::default()
    };
    let old = mint(
        &pool,
        &tenant,
        "rotation-test",
        Some("original-owner"),
        options.clone(),
    )
    .await?;
    let body = old.raw_key.strip_prefix("tlane_").unwrap();
    assert!(lookup_tenant_by_key_body(&pool, body).await?.is_some()); // warm before rotation
    let other = tracelane_shared::TenantId::from_jwt_claim(Uuid::new_v4());
    assert!(
        rotate(&pool, &other, old.api_key.id, "other-owner", 1)
            .await?
            .is_none()
    );
    let rotated = rotate(&pool, &tenant, old.api_key.id, "rotating-owner", 1)
        .await?
        .unwrap();
    assert_eq!(rotated.options.scope, options.scope);
    assert_eq!(rotated.options.expires_at, old.api_key.expires_at);
    assert_eq!(
        rotated.options.budget_usd_monthly,
        options.budget_usd_monthly
    );
    assert_eq!(rotated.options.rate_limit_rpm, options.rate_limit_rpm);
    assert_eq!(rotated.options.budget_reset, options.budget_reset);
    assert!(rotated.options.velocity_breaker);
    assert!(
        lookup_tenant_by_key_body(&pool, body).await?.is_some(),
        "cold lookup accepts scheduled future revocation"
    );
    assert!(
        lookup_tenant_by_key_body(
            &pool,
            rotated.minted.raw_key.strip_prefix("tlane_").unwrap()
        )
        .await?
        .is_some()
    );
    assert!(
        lookup_tenant_by_key_body_at(&pool, body, rotated.revoked_at)
            .await?
            .is_none(),
        "warm lookup refuses exactly at grace deadline"
    );
    let client = pool.get().await?;
    let audit = client.query_one("SELECT actor_user_id, after_json::text FROM admin_audit_log WHERE actor_workspace_id = $1 AND target_id = $2 AND action = 'api_key.rotate'", &[&tenant_id, &old.api_key.id.to_string()]).await?;
    assert_eq!(audit.get::<_, &str>(0), "rotating-owner");
    let json: serde_json::Value = serde_json::from_str(audit.get(1))?;
    assert_eq!(json["successorId"], rotated.minted.api_key.id.to_string());
    assert!(!audit.get::<_, &str>(1).contains(&rotated.minted.raw_key));
    let minter: Option<String> = client
        .query_one(
            "SELECT minted_by FROM api_keys WHERE id = $1",
            &[&rotated.minted.api_key.id],
        )
        .await?
        .get(0);
    assert_eq!(minter.as_deref(), Some("original-owner"));
    client.execute("UPDATE api_keys SET revoked_at = clock_timestamp() - interval '1 second' WHERE id = $1", &[&old.api_key.id]).await?;
    invalidate(peppered_lookup(body)?).await;
    assert!(
        lookup_tenant_by_key_body(&pool, body).await?.is_none(),
        "cold lookup refuses elapsed revocation"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn rotation_has_one_winner_and_zero_grace_revokes_immediately() -> Result<()> {
    use db::api_keys::*;
    let pool = test_pool().await?;
    let id = Uuid::new_v4();
    db::tenants::create(&pool, id, "rotation-race", "free").await?;
    let tenant = tracelane_shared::TenantId::from_jwt_claim(id);
    let _ = init_pepper(&"11".repeat(32));
    let old = mint(&pool, &tenant, "legacy", None, MintOptions::default()).await?;
    let body = old.raw_key.strip_prefix("tlane_").unwrap();
    assert!(lookup_tenant_by_key_body(&pool, body).await?.is_some());
    let (a, b) = tokio::join!(
        rotate(&pool, &tenant, old.api_key.id, "owner-a", 0),
        rotate(&pool, &tenant, old.api_key.id, "owner-b", 0)
    );
    let (a, b) = (a?, b?);
    assert_ne!(
        a.is_some(),
        b.is_some(),
        "concurrent rotations must mint exactly one successor"
    );
    let rotated = a.or(b).unwrap();
    assert!(
        rotated.minted.api_key.scope.is_none(),
        "legacy scope must remain NULL"
    );
    assert!(lookup_tenant_by_key_body(&pool, body).await?.is_none());
    assert!(
        lookup_tenant_by_key_body(
            &pool,
            rotated.minted.raw_key.strip_prefix("tlane_").unwrap()
        )
        .await?
        .is_some()
    );
    let client = pool.get().await?;
    let keys: i64 = client
        .query_one("SELECT count(*) FROM api_keys WHERE tenant_id = $1", &[&id])
        .await?
        .get(0);
    // OG-35: `mint` now records `api_key.create` too, so count the ROTATIONS.
    let audits: i64 = client
        .query_one(
            "SELECT count(*) FROM admin_audit_log
             WHERE actor_workspace_id = $1 AND action = 'api_key.rotate'",
            &[&id],
        )
        .await?
        .get(0);
    assert_eq!((keys, audits), (2, 1));
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn rotation_rolls_back_on_audit_failure_and_reads_seeded_policy() -> Result<()> {
    use db::api_keys::*;
    let pool = test_pool().await?;
    let id = Uuid::new_v4();
    db::tenants::create(&pool, id, "rotation-atomic", "free").await?;
    let tenant = tracelane_shared::TenantId::from_jwt_claim(id);
    let _ = init_pepper(&"11".repeat(32));
    let old = mint(&pool, &tenant, "atomic", None, MintOptions::default()).await?;
    let client = pool.get().await?;
    assert!(
        rotation_grace_hours(&pool).await.is_err(),
        "missing policy must not invent a default"
    );
    let seed: serde_json::Value =
        serde_json::from_str(include_str!("../../../apps/web/db/plans.v3.json"))?;
    let hours = seed["policy"]["key_rotation_grace_hours"].as_i64().unwrap();
    client.execute("INSERT INTO billing_policy(key, value) VALUES ('key_rotation_grace_hours', $1::text::jsonb)", &[&hours.to_string()]).await?;
    assert_eq!(rotation_grace_hours(&pool).await?, hours);
    client.batch_execute("ALTER TABLE admin_audit_log ADD CONSTRAINT rotation_test_refusal CHECK (action <> 'api_key.rotate')").await?;
    assert!(
        rotate(&pool, &tenant, old.api_key.id, "owner", hours)
            .await
            .is_err()
    );
    let row = client
        .query_one(
            "SELECT count(*), count(revoked_at) FROM api_keys WHERE tenant_id = $1",
            &[&id],
        )
        .await?;
    assert_eq!(
        (row.get::<_, i64>(0), row.get::<_, i64>(1)),
        (1, 0),
        "failed audit rolls back both key writes"
    );
    client
        .batch_execute("ALTER TABLE admin_audit_log DROP CONSTRAINT rotation_test_refusal")
        .await?;
    assert!(
        rotate(&pool, &tenant, old.api_key.id, "owner", hours)
            .await?
            .is_some()
    );
    Ok(())
}

// ── SET-38: edit a key's limits in place (spec §7 proofs 2-5) ───────────────

/// Mint a key for a fresh tenant and return (pool, tenant, key, body).
async fn set38_fixture(
    minted_by: Option<&str>,
    opts: db::api_keys::MintOptions,
) -> Result<(
    deadpool_postgres::Pool,
    tracelane_shared::TenantId,
    db::api_keys::MintedKey,
    String,
)> {
    let pool = test_pool().await?;
    let tenant_id = Uuid::new_v4();
    db::tenants::create(&pool, tenant_id, "set38", "free").await?;
    let tenant = tracelane_shared::TenantId::from_jwt_claim(tenant_id);
    let _ = db::api_keys::init_pepper(&"11".repeat(32));
    let key = db::api_keys::mint(&pool, &tenant, "set38-key", minted_by, opts).await?;
    let body = key.raw_key.strip_prefix("tlane_").unwrap().to_string();
    Ok((pool, tenant, key, body))
}

fn scoped(scope: &[&str]) -> db::api_keys::MintOptions {
    db::api_keys::MintOptions {
        scope: Some(scope.iter().map(|s| (*s).to_string()).collect()),
        ..Default::default()
    }
}

/// Proof 3 — a WARM key's next request carries the new limits. Differential: the
/// same narrowing written straight to the row (no invalidation) leaves the warm
/// cache answering with the OLD scope, which is the state `update` must not leave.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn set38_update_binds_on_the_next_request_of_a_warm_key() -> Result<()> {
    use db::api_keys::*;
    use tracelane_shared::api_scope::Scope;
    let (pool, tenant, key, body) = set38_fixture(Some("owner"), scoped(&["chat", "read"])).await?;
    // A control key in the same tenant, narrowed by a raw UPDATE with no invalidate.
    let control = mint(
        &pool,
        &tenant,
        "control",
        Some("owner"),
        scoped(&["chat", "read"]),
    )
    .await?;
    let control_body = control.raw_key.strip_prefix("tlane_").unwrap();
    for b in [body.as_str(), control_body] {
        let warm = lookup_tenant_by_key_body(&pool, b).await?.expect("warm");
        assert!(warm.scope.allows(Scope::Chat), "warm-up: chat is allowed");
    }
    let client = pool.get().await?;
    client
        .execute(
            "UPDATE api_keys SET scope = ARRAY['read'] WHERE id = $1",
            &[&control.api_key.id],
        )
        .await?;
    assert!(
        lookup_tenant_by_key_body(&pool, control_body)
            .await?
            .expect("still cached")
            .scope
            .allows(Scope::Chat),
        "falsification: without the invalidation the warm entry still grants chat"
    );

    let patch = KeyPatch {
        scope: Some(vec!["read".into()]),
        rate_limit_rpm: Some(Some(2)),
        budget_usd_monthly: Some(Some(0.0001)),
        budget_reset: Some(tracelane_shared::spend::BudgetReset::Daily),
        ..Default::default()
    };
    let out = update(
        &pool,
        &tenant,
        key.api_key.id,
        KeyEditor::Any,
        &patch,
        "owner",
    )
    .await?;
    let UpdateOutcome::Updated { record, changed } = out else {
        panic!("expected Updated, got {out:?}");
    };
    assert_eq!(
        changed,
        vec![
            "scope",
            "budget_usd_monthly",
            "rate_limit_rpm",
            "budget_reset"
        ]
    );
    assert_eq!(record.scope, Some(vec!["read".to_string()]));
    let next = lookup_tenant_by_key_body(&pool, &body)
        .await?
        .expect("the key still authenticates");
    assert!(
        !next.scope.allows(Scope::Chat),
        "the very next request must be refused chat (403 insufficient_scope)"
    );
    assert!(next.scope.allows(Scope::Read));
    assert_eq!(
        next.rate_limit_rpm,
        Some(2),
        "the new RPM binds next request"
    );
    assert_eq!(next.budget_usd_monthly, Some(0.0001));
    assert_eq!(
        next.budget_reset,
        tracelane_shared::spend::BudgetReset::Daily
    );

    // The audit row carries ONLY the changed fields, before and after.
    let audit = client
        .query_one(
            "SELECT actor_user_id, before_json, after_json FROM admin_audit_log
             WHERE actor_workspace_id = $1 AND action = 'api_key.update' AND target_id = $2",
            &[tenant.as_uuid(), &key.api_key.id.to_string()],
        )
        .await?;
    assert_eq!(audit.get::<_, &str>(0), "owner");
    let before: serde_json::Value = audit.get(1);
    let after: serde_json::Value = audit.get(2);
    assert_eq!(
        after,
        serde_json::json!({
            "scope": ["read"], "rate_limit_rpm": 2,
            "budget_usd_monthly": 0.0001, "budget_reset": "daily"
        })
    );
    assert_eq!(
        before,
        serde_json::json!({
            "scope": ["chat", "read"], "rate_limit_rpm": null,
            "budget_usd_monthly": null, "budget_reset": "monthly"
        })
    );
    Ok(())
}

/// Proof 4 — a legacy NULL-scope key is narrowed IN PLACE: same secret, same
/// lookup hash, and it keeps authenticating with the narrower grant.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn set38_legacy_key_is_narrowed_in_place_and_keeps_its_secret() -> Result<()> {
    use db::api_keys::*;
    use tracelane_shared::api_scope::Scope;
    let (pool, tenant, key, body) = set38_fixture(None, MintOptions::default()).await?;
    let client = pool.get().await?;
    let hash_before: Vec<u8> = client
        .query_one(
            "SELECT lookup_hash FROM api_keys WHERE id = $1",
            &[&key.api_key.id],
        )
        .await?
        .get(0);
    let warm = lookup_tenant_by_key_body(&pool, &body)
        .await?
        .expect("warm");
    assert_eq!(
        warm.scope,
        tracelane_shared::api_scope::KeyScope::LegacyFullSurface
    );
    let patch = KeyPatch {
        scope: Some(vec!["read".into()]),
        ..Default::default()
    };
    let out = update(
        &pool,
        &tenant,
        key.api_key.id,
        KeyEditor::Any,
        &patch,
        "owner",
    )
    .await?;
    assert!(matches!(out, UpdateOutcome::Updated { ref changed, .. } if changed == &vec!["scope"]));
    let hash_after: Vec<u8> = client
        .query_one(
            "SELECT lookup_hash FROM api_keys WHERE id = $1",
            &[&key.api_key.id],
        )
        .await?
        .get(0);
    assert_eq!(
        hash_before, hash_after,
        "narrowing must not change the secret"
    );
    let next = lookup_tenant_by_key_body(&pool, &body)
        .await?
        .expect("same secret still works");
    assert!(next.scope.allows(Scope::Read), "GET /v1/traces still 200");
    assert!(!next.scope.allows(Scope::Chat), "chat now 403");
    Ok(())
}

/// Proof 2 (the database half) — every refusal is decided under the row lock and
/// writes nothing: another tenant's key, a member on someone else's key, a
/// revoked key, an expired key, a retiring key. Plus the no-op rule.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn set38_update_refusals_write_nothing() -> Result<()> {
    use db::api_keys::*;
    let (pool, tenant, key, _body) = set38_fixture(Some("owner-user"), scoped(&["chat"])).await?;
    let client = pool.get().await?;
    let rpm2 = KeyPatch {
        rate_limit_rpm: Some(Some(2)),
        ..Default::default()
    };
    let c = &client;
    let t = &tenant;
    // OG-35: `mint` records `api_key.create` too — count the EDITS this test makes.
    let audits = || async move {
        let n: i64 = c
            .query_one(
                "SELECT count(*) FROM admin_audit_log
                  WHERE actor_workspace_id = $1 AND action = 'api_key.update'",
                &[t.as_uuid()],
            )
            .await
            .unwrap()
            .get(0);
        n
    };
    let rpm_of = |id: Uuid| async move {
        {
            let v: Option<i32> = c
                .query_one("SELECT rate_limit_rpm FROM api_keys WHERE id = $1", &[&id])
                .await
                .unwrap()
                .get(0);
            v
        }
    };

    // Tenant B's JWT naming tenant A's key id: the same 404 as a missing key.
    let other_id = Uuid::new_v4();
    db::tenants::create(&pool, other_id, "set38-other", "free").await?;
    let other = tracelane_shared::TenantId::from_jwt_claim(other_id);
    assert_eq!(
        update(
            &pool,
            &other,
            key.api_key.id,
            KeyEditor::Any,
            &rpm2,
            "b-owner"
        )
        .await?,
        UpdateOutcome::NotFound
    );
    // A member editing a key another user minted.
    assert_eq!(
        update(
            &pool,
            &tenant,
            key.api_key.id,
            KeyEditor::MintedBy("member-user"),
            &rpm2,
            "member-user"
        )
        .await?,
        UpdateOutcome::Forbidden
    );
    assert_eq!(rpm_of(key.api_key.id).await, None, "refusals write nothing");
    assert_eq!(audits().await, 0, "refusals audit nothing");
    // The same member on a key THEY minted is allowed.
    let own = mint(
        &pool,
        &tenant,
        "mine",
        Some("member-user"),
        scoped(&["read"]),
    )
    .await?;
    assert!(matches!(
        update(
            &pool,
            &tenant,
            own.api_key.id,
            KeyEditor::MintedBy("member-user"),
            &rpm2,
            "member-user"
        )
        .await?,
        UpdateOutcome::Updated { .. }
    ));
    assert_eq!(rpm_of(own.api_key.id).await, Some(2));
    // A no-op (every value equal to the current one): 200, changed [], no audit row.
    let before = audits().await;
    let UpdateOutcome::Updated { changed, .. } = update(
        &pool,
        &tenant,
        own.api_key.id,
        KeyEditor::Any,
        &rpm2,
        "owner-user",
    )
    .await?
    else {
        panic!("a no-op is still Updated");
    };
    assert!(changed.is_empty());
    assert_eq!(audits().await, before, "a no-op writes no audit row");

    // Expired: 404.
    let expired = mint(
        &pool,
        &tenant,
        "expired",
        Some("owner-user"),
        scoped(&["read"]),
    )
    .await?;
    client
        .execute(
            "UPDATE api_keys SET expires_at = clock_timestamp() - interval '1 second' WHERE id = $1",
            &[&expired.api_key.id],
        )
        .await?;
    assert_eq!(
        update(
            &pool,
            &tenant,
            expired.api_key.id,
            KeyEditor::Any,
            &rpm2,
            "owner-user"
        )
        .await?,
        UpdateOutcome::NotFound
    );
    // Retiring (rotated, in its grace window): 409 — edit the successor.
    let rotated = rotate(&pool, &tenant, key.api_key.id, "owner-user", 1)
        .await?
        .expect("rotated");
    assert!(matches!(
        update(&pool, &tenant, key.api_key.id, KeyEditor::Any, &rpm2, "owner-user").await?,
        UpdateOutcome::Retiring { revoked_at } if revoked_at == rotated.revoked_at
    ));
    // Revoked: 404.
    revoke(&pool, rotated.minted.api_key.id).await?;
    assert_eq!(
        update(
            &pool,
            &tenant,
            rotated.minted.api_key.id,
            KeyEditor::Any,
            &rpm2,
            "owner-user"
        )
        .await?,
        UpdateOutcome::NotFound
    );
    assert_eq!(rpm_of(expired.api_key.id).await, None);
    assert_eq!(rpm_of(rotated.minted.api_key.id).await, None);
    Ok(())
}

/// Proof 5 — fail CLOSED: an audit insert that fails rolls the edit back, and the
/// warm cache is not invalidated onto a row that did not change.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn set38_audit_failure_rolls_the_edit_back() -> Result<()> {
    use db::api_keys::*;
    let (pool, tenant, key, body) = set38_fixture(Some("owner"), scoped(&["chat"])).await?;
    let client = pool.get().await?;
    client
        .batch_execute(
            "ALTER TABLE admin_audit_log ADD CONSTRAINT set38_test_refusal CHECK (action <> 'api_key.update')",
        )
        .await?;
    let patch = KeyPatch {
        rate_limit_rpm: Some(Some(2)),
        name: Some("renamed".into()),
        ..Default::default()
    };
    assert!(
        update(
            &pool,
            &tenant,
            key.api_key.id,
            KeyEditor::Any,
            &patch,
            "owner"
        )
        .await
        .is_err(),
        "an audit failure must fail the edit"
    );
    let row = client
        .query_one(
            "SELECT name, rate_limit_rpm FROM api_keys WHERE id = $1",
            &[&key.api_key.id],
        )
        .await?;
    assert_eq!(row.get::<_, &str>(0), "set38-key", "the row is unchanged");
    assert_eq!(row.get::<_, Option<i32>>(1), None);
    client
        .batch_execute("ALTER TABLE admin_audit_log DROP CONSTRAINT set38_test_refusal")
        .await?;
    assert_eq!(
        lookup_tenant_by_key_body(&pool, &body)
            .await?
            .expect("works")
            .rate_limit_rpm,
        None
    );
    Ok(())
}

/// B-586 / SET-38 B6 — a revoke through the gateway ends a WARM key on its very
/// next request. Differential: the legacy row-only `revoke()` (what the web
/// Drizzle UPDATE did) leaves the warm key authenticating.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn b586_gateway_revoke_ends_a_warm_key_on_its_next_request() -> Result<()> {
    use db::api_keys::*;
    let (pool, tenant, key, body) = set38_fixture(Some("owner"), scoped(&["chat"])).await?;
    let legacy = mint(
        &pool,
        &tenant,
        "legacy-path",
        Some("owner"),
        scoped(&["chat"]),
    )
    .await?;
    let legacy_body = legacy.raw_key.strip_prefix("tlane_").unwrap();
    assert!(lookup_tenant_by_key_body(&pool, &body).await?.is_some());
    assert!(
        lookup_tenant_by_key_body(&pool, legacy_body)
            .await?
            .is_some()
    );

    revoke(&pool, legacy.api_key.id).await?;
    assert!(
        lookup_tenant_by_key_body(&pool, legacy_body)
            .await?
            .is_some(),
        "falsification: a row-only revoke leaves the warm key working (B-586)"
    );

    // Another tenant cannot revoke it.
    let other_id = Uuid::new_v4();
    db::tenants::create(&pool, other_id, "b586-other", "free").await?;
    let other = tracelane_shared::TenantId::from_jwt_claim(other_id);
    assert!(
        revoke_key(&pool, &other, key.api_key.id, "b-owner")
            .await?
            .is_none()
    );
    assert!(lookup_tenant_by_key_body(&pool, &body).await?.is_some());

    let revoked = revoke_key(&pool, &tenant, key.api_key.id, "owner")
        .await?
        .expect("revoked");
    assert!(revoked <= chrono::Utc::now(), "revoked NOW, not scheduled");
    assert!(
        lookup_tenant_by_key_body(&pool, &body).await?.is_none(),
        "the next request of a warm, revoked key must be a 401"
    );
    assert!(
        revoke_key(&pool, &tenant, key.api_key.id, "owner")
            .await?
            .is_none(),
        "a second revoke is a 404, not a second audit row"
    );
    let client = pool.get().await?;
    let audit = client
        .query_one(
            "SELECT count(*), max(actor_user_id) FROM admin_audit_log
             WHERE actor_workspace_id = $1 AND action = 'api_key.revoke' AND target_id = $2",
            &[tenant.as_uuid(), &key.api_key.id.to_string()],
        )
        .await?;
    assert_eq!(audit.get::<_, i64>(0), 1);
    assert_eq!(audit.get::<_, Option<&str>>(1), Some("owner"));

    // A retiring key is revoked NOW (its grace ends early).
    let retiring = mint(&pool, &tenant, "retiring", Some("owner"), scoped(&["chat"])).await?;
    let retiring_body = retiring.raw_key.strip_prefix("tlane_").unwrap();
    rotate(&pool, &tenant, retiring.api_key.id, "owner", 24)
        .await?
        .expect("rotated");
    assert!(
        lookup_tenant_by_key_body(&pool, retiring_body)
            .await?
            .is_some()
    );
    revoke_key(&pool, &tenant, retiring.api_key.id, "owner")
        .await?
        .expect("a retiring key can still be revoked");
    assert!(
        lookup_tenant_by_key_body(&pool, retiring_body)
            .await?
            .is_none()
    );
    Ok(())
}

/// B-586 — fail CLOSED: an audit failure rolls the revocation back.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn b586_revoke_audit_failure_rolls_back() -> Result<()> {
    use db::api_keys::*;
    let (pool, tenant, key, _body) = set38_fixture(Some("owner"), scoped(&["chat"])).await?;
    let client = pool.get().await?;
    client
        .batch_execute(
            "ALTER TABLE admin_audit_log ADD CONSTRAINT b586_test_refusal CHECK (action <> 'api_key.revoke')",
        )
        .await?;
    assert!(
        revoke_key(&pool, &tenant, key.api_key.id, "owner")
            .await
            .is_err()
    );
    let revoked: bool = client
        .query_one(
            "SELECT revoked_at IS NOT NULL FROM api_keys WHERE id = $1",
            &[&key.api_key.id],
        )
        .await?
        .get(0);
    assert!(
        !revoked,
        "a failed audit must leave the key live, not half-revoked"
    );
    client
        .batch_execute("ALTER TABLE admin_audit_log DROP CONSTRAINT b586_test_refusal")
        .await?;
    Ok(())
}

/// `get` — one key of THIS tenant; revoked and foreign keys read as absent.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn set38_get_reads_one_key_of_this_tenant_only() -> Result<()> {
    use db::api_keys::*;
    let (pool, tenant, key, _body) = set38_fixture(
        Some("owner"),
        MintOptions {
            scope: Some(vec!["read".into()]),
            budget_usd_monthly: Some(12.5),
            rate_limit_rpm: Some(30),
            budget_reset: Some(tracelane_shared::spend::BudgetReset::Weekly),
            velocity_breaker: true,
            ..Default::default()
        },
    )
    .await?;
    let got = get(&pool, &tenant, key.api_key.id).await?.expect("found");
    assert_eq!(got.budget_usd_monthly, Some(12.5));
    assert_eq!(got.rate_limit_rpm, Some(30));
    assert_eq!(
        got.budget_reset,
        tracelane_shared::spend::BudgetReset::Weekly
    );
    assert!(got.velocity_breaker);
    assert_eq!(got.minted_by.as_deref(), Some("owner"));
    let other = tracelane_shared::TenantId::from_jwt_claim(Uuid::new_v4());
    assert!(get(&pool, &other, key.api_key.id).await?.is_none());
    revoke_key(&pool, &tenant, key.api_key.id, "owner").await?;
    assert!(get(&pool, &tenant, key.api_key.id).await?.is_none());
    Ok(())
}

fn require_url() -> String {
    url().expect(
        "POSTGRES_TEST_URL not set — run with `POSTGRES_TEST_URL=postgres://… \
         cargo test --features prompt-promotion-preview --test \
         postgres_tenant_integration -- --ignored`",
    )
}

/// Create a FRESH database and return a URL pointing at it.
///
/// `db::apply_migrations` says so in its own doc comment: *"Fresh-database
/// helper for integration tests only. The Drizzle SQL is NOT `IF NOT
/// EXISTS`-guarded, so re-running against a populated DB fails."* Every test in
/// this binary calls `test_pool()`, so before this existed the SECOND test to
/// run died on `type "cmk_algorithm" already exists` — the tests could only ever
/// have passed one at a time, which is part of why nothing ran them.
///
/// One database per call, named from a UUID, so the binary is parallel-safe.
/// Returns the NAME; the caller overrides `cfg.dbname`, so no URL rewriting is
/// needed and no new dependency is pulled in for it.
///
/// B-494 (2026-09-21): with `template`, the database is CLONED from an already-migrated
/// one (`CREATE DATABASE … TEMPLATE …`, a file copy) instead of being migrated again —
/// the 47-migration replay was ~two thirds of every test's run time, thirteen times over.
/// Postgres refuses to clone a template while another session is connected to it
/// (SQLSTATE 55006); the migrating pool is closed before this is called, and the
/// server can lag the socket close by a few ms, so the clone retries briefly.
async fn create_fresh_database(template: Option<&str>) -> Result<String> {
    let admin_url = require_url();
    let (client, conn) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls).await?;
    let handle = tokio::spawn(conn);
    let db = format!("tlane_it_{}", Uuid::new_v4().simple());
    let stmt = match template {
        Some(tpl) => format!("CREATE DATABASE {db} TEMPLATE {tpl}"),
        None => format!("CREATE DATABASE {db}"),
    };
    let mut created = client.batch_execute(&stmt).await;
    let mut attempts = 0;
    while let Err(e) = &created {
        let busy = e.code() == Some(&tokio_postgres::error::SqlState::OBJECT_IN_USE);
        if !busy || attempts >= 40 {
            break;
        }
        attempts += 1;
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        created = client.batch_execute(&stmt).await;
    }
    drop(client);
    let _ = handle.await;
    created.map_err(|e| anyhow::anyhow!("{stmt} failed (needs createdb): {e}"))?;
    Ok(db)
}

/// B-494: the ONE migrated database this test binary clones from. Built by the first
/// test to need a pool, under a `OnceCell` so two tests at `RUST_TEST_THREADS=2` do not
/// both migrate; the migrating pool is closed before the name is handed out, because a
/// template with an open session cannot be cloned.
static TEMPLATE_DB: tokio::sync::OnceCell<String> = tokio::sync::OnceCell::const_new();

async fn template_database() -> Result<&'static str> {
    TEMPLATE_DB
        .get_or_try_init(|| async {
            let db = create_fresh_database(None).await?;
            let pool = pool_for(&db)?;
            db::apply_migrations(&pool).await?;
            pool.close();
            Ok::<String, anyhow::Error>(db)
        })
        .await
        .map(String::as_str)
}

async fn test_pool() -> Result<deadpool_postgres::Pool> {
    let template = template_database().await?;
    let fresh_db = create_fresh_database(Some(template)).await?;
    // Cloned from the migrated template — `apply_migrations` must NOT run again here
    // (the Drizzle SQL is not `IF NOT EXISTS`-guarded, see `create_fresh_database`).
    pool_for(&fresh_db)
}

fn pool_for(fresh_db: &str) -> Result<deadpool_postgres::Pool> {
    // Re-implement build_pool inline — db::build_pool reads POSTGRES_URL,
    // which we deliberately don't set in CI test runs.
    let url = require_url();
    let pg_cfg: tokio_postgres::Config = url.parse()?;
    let mut cfg = deadpool_postgres::Config::new();
    // tokio_postgres::config::Host has different variants per OS — use a
    // cfg-branched helper so neither target trips unreachable_patterns.
    fn host_to_string(host: &tokio_postgres::config::Host) -> Option<String> {
        #[cfg(unix)]
        {
            match host {
                tokio_postgres::config::Host::Tcp(s) => Some(s.clone()),
                tokio_postgres::config::Host::Unix(p) => Some(p.to_string_lossy().into_owned()),
            }
        }
        #[cfg(not(unix))]
        {
            match host {
                tokio_postgres::config::Host::Tcp(s) => Some(s.clone()),
            }
        }
    }
    cfg.host = pg_cfg.get_hosts().first().and_then(host_to_string);
    cfg.port = pg_cfg.get_ports().first().copied();
    cfg.user = pg_cfg.get_user().map(str::to_owned);
    cfg.password = pg_cfg
        .get_password()
        .map(|p| String::from_utf8_lossy(p).to_string());
    // Point at the FRESH database, not the one in the URL — see
    // `create_fresh_database` for why re-migrating a populated DB cannot work.
    cfg.dbname = Some(fresh_db.to_owned());
    let pool = cfg.create_pool(
        Some(deadpool_postgres::Runtime::Tokio1),
        tokio_postgres::NoTls,
    )?;
    Ok(pool)
}

#[tokio::test]
#[ignore]
async fn create_tenant_and_lookup_by_api_key() -> Result<()> {
    let pool = test_pool().await?;

    let tenant_id = Uuid::new_v4();
    let _tenant = db::tenants::create(&pool, tenant_id, "test-tenant", "free").await?;

    // Pepper required for peppered_lookup. Use a deterministic test value.
    let _ = db::api_keys::init_pepper(&"11".repeat(32));

    let key_body = format!("test_key_{}", Uuid::new_v4().simple());
    let material = db::api_keys::KeyMaterial::from_body(&key_body)?;

    let tenant_for_key = tracelane_shared::TenantId::from_jwt_claim(tenant_id);
    let key_prefix = &key_body[..6];
    let created = db::api_keys::create(
        &pool,
        &tenant_for_key,
        &material,
        "ci-test",
        key_prefix,
        None,
        // A13: `create` is the raw writer — it stores exactly what it is given.
        // Default MintOptions leaves scope/expiry/budget as SQL NULL, which is
        // the LEGACY row shape, and that is deliberately what this test wants:
        // the assertion below is that an unscoped row still authenticates with
        // full surface. The full-set default lives at the HTTP edge
        // (`MintOptions::with_default_scope`), not here.
        &db::api_keys::MintOptions::default(),
    )
    .await?;

    // Hot-path lookup must round-trip
    let resolved = db::api_keys::lookup_tenant_by_key_body(&pool, &key_body).await?;
    // A13: the lookup now also returns the resolved capability, read in the same
    // round-trip that authenticates the key.
    // GWY-43: the lookup returns a `KeyAuth` struct rather than a tuple — it now
    // also carries the key's budget and rate-limit ceilings, read in the same
    // round trip.
    let auth = resolved.expect("api key should resolve");
    let (resolved, key_scope) = (auth.tenant_id, auth.scope);
    assert_eq!(
        auth.budget_usd_monthly, None,
        "a key minted with no budget must resolve as uncapped, not as zero"
    );
    assert_eq!(
        auth.rate_limit_rpm, None,
        "a key minted with no rpm override must inherit the tenant tier"
    );
    assert_eq!(resolved.as_uuid().to_string(), tenant_id.to_string());
    // A key minted without an explicit scope is `scope IS NULL` — the legacy,
    // full-surface case. This is the compatibility guarantee: if it ever
    // regresses to a restricted scope, every key minted before A13 stops working.
    assert_eq!(
        key_scope,
        tracelane_shared::api_scope::KeyScope::LegacyFullSurface,
        "an unscoped key must resolve to the legacy full-surface capability"
    );

    // Unknown key body must NOT resolve
    let unknown = db::api_keys::lookup_tenant_by_key_body(&pool, "nope_does_not_exist").await?;
    assert!(unknown.is_none(), "unknown key body must return None");

    // ── Revocation, and the bound it actually carries ───────────────────────
    //
    // This block used to assert `after_revoke.is_none()` immediately. That
    // asserts a guarantee the product DELIBERATELY DOES NOT MAKE, and it is why
    // this test failed the first time it was ever executed (2026-08-14).
    //
    // `revoke()` writes `revoked_at` and does NOT touch the positives-only auth
    // cache. made that explicit after `pg_notify`-based invalidation was
    // measured unreliable against an autosuspending Neon compute (110
    // drop/reconnect cycles in 21 h): **the cache TTL IS the revocation bound,
    // and it is 60 s** (`DEFAULT_AUTH_CACHE_TTL_SECS`). Confirmed against
    // production the same day — a deleted key returned 200 at t+45 s and 401
    // from t+60 s.
    //
    // So the honest assertion is in two halves: the row is revoked, and the
    // cache is what may still answer until it expires.
    db::api_keys::revoke(&pool, created.id).await?;
    let still_cached = db::api_keys::lookup_tenant_by_key_body(&pool, &key_body).await?;
    assert!(
        still_cached.is_some(),
        "documented bound: a revoked key may still resolve from the positives-only \
         auth cache for up to DEFAULT_AUTH_CACHE_TTL_SECS. If this now fails, \
         revocation became immediate — a GOOD change, but update this pin and \
         the B-178 note rather than deleting the assertion."
    );

    // Drop the cached entry and the revocation must be visible at once, which
    // proves the row itself is genuinely revoked and only the cache was holding
    // it — the discriminating half.
    db::api_keys::invalidate(db::api_keys::peppered_lookup(&key_body)?).await;
    let after_invalidate = db::api_keys::lookup_tenant_by_key_body(&pool, &key_body).await?;
    assert!(
        after_invalidate.is_none(),
        "once the cache entry is gone, a revoked api key must not resolve"
    );

    Ok(())
}

#[tokio::test]
#[ignore]
async fn polar_id_round_trip_finds_tenant() -> Result<()> {
    let pool = test_pool().await?;

    let tenant_id = Uuid::new_v4();
    let _tenant = db::tenants::create(&pool, tenant_id, "billing-test", "free").await?;

    let tenant_wrapped = tracelane_shared::TenantId::from_jwt_claim(tenant_id);
    let cust_id = format!("cust_polar_{}", Uuid::new_v4().simple());
    let sub_id = format!("sub_polar_{}", Uuid::new_v4().simple());

    db::tenants::set_polar_ids(&pool, &tenant_wrapped, &cust_id, Some(&sub_id)).await?;

    let by_customer = db::tenants::get_by_polar_customer(&pool, &cust_id).await?;
    let found = by_customer.expect("customer lookup should resolve");
    assert_eq!(found.tenant_id, tenant_id);
    assert_eq!(found.polar_customer_id.as_deref(), Some(cust_id.as_str()));
    assert_eq!(
        found.polar_subscription_id.as_deref(),
        Some(sub_id.as_str())
    );

    // The `set_plan_tier` upgrade assertion was DELETED with the function it
    // exercised (founder ruling 2026-08-14): a gateway-side plan writer with no
    // production caller is an entry point into the one invariant B-241 shows we
    // cannot hold. Plan state moves through the Polar webhook only.

    Ok(())
}

/// Smoke test runs without Postgres — proves the authoritative Drizzle
/// migration SQL embeds correctly + the peppered_lookup derivation honours its
/// 32-byte contract. (: the old `infra/dev/postgres/migrations/` set was
/// retired; Drizzle `apps/web/db/migrations/` is the single source of truth.)
#[test]
fn migration_sql_embeds_and_hash_is_stable() {
    let m00 = include_str!("../../../apps/web/db/migrations/0000_initial_baseline.sql");
    assert!(m00.contains("CREATE TABLE \"tenants\""));
    assert!(m00.contains("CREATE TABLE \"api_keys\""));
    assert!(m00.contains("CREATE TABLE \"plan_entitlements\""));

    let m06 = include_str!("../../../apps/web/db/migrations/0006_b084_users_name_guardrails.sql");
    assert!(m06.contains("CREATE TABLE \"users\""));
    assert!(m06.contains("f_guardrail_r2"));

    // peppered_lookup is the deterministic 32-byte lookup derivation.
    let _ = db::api_keys::init_pepper(&"22".repeat(32));
    let h1 = db::api_keys::peppered_lookup("abc123").unwrap();
    let h2 = db::api_keys::peppered_lookup("abc123").unwrap();
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 32);
}

/// **EVL-29 — the `jsonb` bind, against a REAL Postgres, in BOTH directions.**
///
/// THE DEFECT THIS EXISTS FOR, found on prod 2026-08-29 at the first real
/// request: `create_queue` bound `filter_json` as `$4::jsonb` while passing a
/// `&str`, and tokio-postgres refuses that — *"cannot convert between the Rust
/// type `&str` and the Postgres type `jsonb`"*. Every queue creation 500'd.
///
/// **THAT IS THE SAME CLASS THIS FILE'S OWN HEADER RECORDS FOR A13:**
/// `$9::numeric` bound with an `Option<String>`, which broke `POST /v1/keys`
/// for two days. A `$n::<type>` cast makes Postgres infer the PLACEHOLDER as
/// that type, so the Rust value must map to it directly — the cast does not
/// convert for you. Second occurrence of the class, so it gets a test.
///
/// **This asserts the BROKEN direction FAILS**, not just that the fixed one
/// passes. A test that only exercises the working binding would still pass if
/// someone reintroduced the cast, which is the whole failure mode.
///
/// The 29 `annotation_routes` unit tests passed throughout — they run against
/// the in-memory mock, which proves handler logic and can NEVER prove wire
/// types. Nothing exercised these columns against a real database until now.
#[tokio::test]
#[ignore]
async fn evl29_jsonb_columns_reject_a_str_and_accept_a_value() -> Result<()> {
    let pool = test_pool().await?;
    let client = pool.get().await?;

    let tenant_id = Uuid::new_v4();
    let _tenant = db::tenants::create(&pool, tenant_id, "evl29-jsonb-test", "free").await?;

    let filter = serde_json::json!({
        "source": { "kind": "online_eval_score", "max_score": 0.5 },
        "window_hours": 168
    });
    let rubric = serde_json::json!([
        { "key": "ideal_answer", "label": "Ideal", "type": "text", "required": true }
    ]);

    const INSERT: &str = "INSERT INTO annotation_queues \
         (id, tenant_id, name, filter_json, rubric_json, default_dataset_id, \
          expected_output_field, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)";

    // ── THE BROKEN DIRECTION. This is what shipped, and it must FAIL. ───────
    let as_text = filter.to_string();
    let broken = client
        .execute(
            INSERT,
            &[
                &Uuid::new_v4(),
                &tenant_id,
                &"broken",
                &as_text, // a String, against a jsonb column
                &rubric.to_string(),
                &Uuid::new_v4(),
                &"ideal_answer",
                &"test",
            ],
        )
        .await;
    // Asserted as `is_err()` and NOT on the message text, matching
    // `budget_param_serialization_contract`'s idiom in `db::api_keys`. The
    // first version of this checked the string and failed: tokio-postgres's
    // top-level `Display` is only "error serializing parameter 3", and the
    // "cannot convert between the Rust type `&str` and the Postgres type
    // `jsonb`" detail lives in the error's SOURCE CHAIN. Coupling a test to a
    // dependency's Display format makes it fail on an upgrade that broke
    // nothing — the refusal itself is the contract.
    assert!(
        broken.is_err(),
        "binding a String to a jsonb column MUST fail — if this ever succeeds, \
         this test has stopped protecting anything"
    );

    // ── THE FIXED DIRECTION: a parsed `Value` maps natively. ────────────────
    let queue_id = Uuid::new_v4();
    let dataset_id = Uuid::new_v4();
    client
        .execute(
            INSERT,
            &[
                &queue_id,
                &tenant_id,
                &"low scores",
                &filter,
                &rubric,
                &dataset_id,
                &"ideal_answer",
                &"test",
            ],
        )
        .await?;

    // Read back as text and re-parse — proving the bytes that landed are the
    // JSON we sent, not a quoted string containing JSON (which is what a
    // successful-but-wrong bind would have produced).
    let row = client
        .query_one(
            "SELECT filter_json::text, rubric_json::text, expected_output_field \
               FROM annotation_queues WHERE id = $1",
            &[&queue_id],
        )
        .await?;
    let back: serde_json::Value = serde_json::from_str(&row.get::<_, String>(0))?;
    assert_eq!(
        back["window_hours"], 168,
        "the stored filter must be a JSON OBJECT, not a string containing JSON"
    );
    let back_rubric: serde_json::Value = serde_json::from_str(&row.get::<_, String>(1))?;
    assert!(
        back_rubric.is_array(),
        "the rubric must round-trip as an array"
    );
    assert_eq!(row.get::<_, String>(2), "ideal_answer");

    // R223's CHECK must be live on the real table: an empty reference field is
    // refused by the DATABASE, not merely by the handler.
    let empty_ref = client
        .execute(
            INSERT,
            &[
                &Uuid::new_v4(),
                &tenant_id,
                &"no reference",
                &filter,
                &rubric,
                &dataset_id,
                &"",
                &"test",
            ],
        )
        .await;
    assert!(
        empty_ref.is_err(),
        "annotation_queues_expected_field_chk must refuse an empty reference field"
    );

    Ok(())
}

// ── B-378: the batched head-advance against a REAL Postgres ────────────────
//
// `append_atomic_batch` is the transaction the audit head-writer runs. Three
// properties, each of which a mock could fake: K events advance the head by
// exactly K with the chain intact; a redelivered batch of the SAME event ids
// consumes ZERO seqs; a batch that is half redelivery, half new appends only
// the new half and chains it from the real head.

fn tenant() -> tracelane_shared::TenantId {
    tracelane_shared::TenantId::from_jwt_claim(Uuid::new_v4())
}

fn fake_hash(seq: u64, prev: &[u8; 32]) -> [u8; 32] {
    // A stand-in for `row_hash_v2` — the test asserts the CHAINING, not the
    // digest; `build_rows` is the caller's, and this one records what it was
    // handed.
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&seq.to_be_bytes());
    h[8..16].copy_from_slice(&prev[..8]);
    h
}

fn hex(h: &[u8; 32]) -> String {
    h.iter().map(|b| format!("{b:02x}")).collect()
}

/// ADR-078 (B): the rows the closure builds — the canonical store writes them.
fn fake_rows(
    tenant: &tracelane_shared::TenantId,
    first_seq: u64,
    prev: [u8; 32],
    kept: &[usize],
) -> Vec<db::ledger::AuditLogRow> {
    let mut p = prev;
    let mut rows = Vec::new();
    for i in 0..kept.len() {
        let seq = first_seq + i as u64;
        let h = fake_hash(seq, &p);
        rows.push(db::ledger::AuditLogRow {
            tenant_id: tenant.to_string(),
            seq,
            event_time: chrono::Utc::now().timestamp_micros(),
            event_type: "test".into(),
            actor: "it".into(),
            payload: "{}".into(),
            prev_hash: hex(&p),
            row_hash: hex(&h),
            rekor_entry_id: None,
            signature: String::new(),
            signing_pubkey: String::new(),
        });
        p = h;
    }
    rows
}

#[tokio::test]
#[ignore]
async fn b378_batch_advances_the_head_by_k_and_chains() -> Result<()> {
    let pool = test_pool().await?;
    let t = tenant();
    let genesis = [7u8; 32];
    let ids: Vec<String> = (0..5)
        .map(|i| format!("evt-{i}-{}", Uuid::new_v4()))
        .collect();
    let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen2 = std::sync::Arc::clone(&seen);
    let t2 = t.clone();
    let out = db::audit_chain_state::append_atomic_batch(
        &pool,
        &t,
        genesis,
        Some(&ids),
        5,
        move |first_seq, prev, kept| {
            seen2.lock().unwrap().push((first_seq, prev, kept.to_vec()));
            Ok(fake_rows(&t2, first_seq, prev, kept))
        },
    )
    .await?
    .expect("five new events must append");
    assert_eq!(out.first_seq, 0, "genesis batch starts at seq 0");
    assert_eq!(out.prev_hash, genesis);
    assert_eq!(out.kept, vec![0, 1, 2, 3, 4]);
    assert_eq!(out.row_hashes.len(), 5);
    assert_eq!(
        out.rows.len(),
        5,
        "the committed rows come back for the copy"
    );
    // Chained: hash i embeds hash i-1's prefix.
    for i in 1..5 {
        assert_eq!(&out.row_hashes[i][8..16], &out.row_hashes[i - 1][..8]);
    }
    let rows = db::audit_chain_state::load_all(&pool).await?;
    let head = rows
        .iter()
        .find(|r| r.tenant_id == t)
        .expect("head row persisted");
    assert_eq!(head.last_seq, 4, "head advanced to the END of the batch");
    assert_eq!(head.last_row_hash, out.row_hashes[4]);
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "ONE build_rows call for the batch"
    );
    // ADR-078 (B): the rows are IN the canonical store, committed with the head —
    // read back from Postgres, not trusted from the return value.
    let range = db::ledger::ledger_range(&pool, &t).await?;
    assert_eq!(
        (range.from, range.to, range.total),
        (Some(0), Some(4), 5),
        "5 canonical rows, seq 0..=4"
    );
    let leaves = db::ledger::read_row_hashes(&pool, &t, 0, 4).await?;
    assert_eq!(
        leaves, out.row_hashes,
        "the canonical leaf set IS the batch's hashes"
    );

    // Redelivery of the SAME five ids: no seq consumed, build_rows never called.
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
    let calls2 = std::sync::Arc::clone(&calls);
    let t3 = t.clone();
    let again = db::audit_chain_state::append_atomic_batch(
        &pool,
        &t,
        genesis,
        Some(&ids),
        5,
        move |first_seq, prev, kept| {
            calls2.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(fake_rows(&t3, first_seq, prev, kept))
        },
    )
    .await?;
    assert!(again.is_none(), "an all-redelivered batch is a no-op");
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    let rows = db::audit_chain_state::load_all(&pool).await?;
    let head = rows.iter().find(|r| r.tenant_id == t).unwrap();
    assert_eq!(head.last_seq, 4, "redelivery must not move the head");
    assert_eq!(
        db::ledger::ledger_range(&pool, &t).await?.total,
        5,
        "redelivery must not write a row either"
    );

    // Half redelivered, half new: only the new two append, chained from seq 4.
    let mixed: Vec<String> = vec![
        ids[1].clone(),
        format!("evt-new-a-{}", Uuid::new_v4()),
        ids[3].clone(),
        format!("evt-new-b-{}", Uuid::new_v4()),
    ];
    let t4 = t.clone();
    let out2 = db::audit_chain_state::append_atomic_batch(
        &pool,
        &t,
        genesis,
        Some(&mixed),
        4,
        move |first_seq, prev, kept| Ok(fake_rows(&t4, first_seq, prev, kept)),
    )
    .await?
    .expect("two new events must append");
    assert_eq!(out2.first_seq, 5);
    assert_eq!(out2.kept, vec![1, 3], "only the NEW ids, in arrival order");
    assert_eq!(
        out2.prev_hash, out.row_hashes[4],
        "chains from the real head"
    );
    let rows = db::audit_chain_state::load_all(&pool).await?;
    let head = rows.iter().find(|r| r.tenant_id == t).unwrap();
    assert_eq!(head.last_seq, 6);
    assert_eq!(
        db::ledger::max_seq(&pool, &t).await?,
        Some(6),
        "rows and head agree"
    );
    Ok(())
}

#[tokio::test]
#[ignore]
async fn b378_a_short_row_vector_refuses_to_advance_the_head() -> Result<()> {
    // build_rows returning fewer rows than events would advance the head past
    // rows that were never written. Fail closed: error, no head movement, no row.
    let pool = test_pool().await?;
    let t = tenant();
    let ids: Vec<String> = (0..3)
        .map(|i| format!("evt-{i}-{}", Uuid::new_v4()))
        .collect();
    let t2 = t.clone();
    let err = db::audit_chain_state::append_atomic_batch(
        &pool,
        &t,
        [1u8; 32],
        Some(&ids),
        3,
        move |first_seq, prev, kept| Ok(fake_rows(&t2, first_seq, prev, &kept[..2])),
    )
    .await
    .expect_err("2 rows for 3 events must be refused");
    assert!(
        format!("{err:#}").contains("refusing to advance the head"),
        "{err:#}"
    );
    let rows = db::audit_chain_state::load_all(&pool).await?;
    assert!(
        rows.iter().all(|r| r.tenant_id != t),
        "the rolled-back genesis row must not persist"
    );
    assert_eq!(
        db::ledger::ledger_range(&pool, &t).await?.total,
        0,
        "no canonical row survives a rolled-back append (ADR-078 B: one transaction)"
    );
    Ok(())
}

// ── B-465: a read asked for N rows must return min(N, rows), never a private cap ──
//
// Found on prod by the ADR-078 deploy's Proof C (2026-09-20): `ledger.rs` clamped every
// read to 10,000 while the export handler paged by 50,000 and stopped on a short page,
// so the 29,691-row dogfood ledger exported as 10,000 rows and the verifier reported
// `anchor_rows_missing` ×3 behind a green exit code. 12,000 rows land in ONE `UNNEST`
// statement (the same path the head-writer uses); the read asks for 50,000.
#[tokio::test]
#[ignore]
async fn b465_a_window_read_returns_every_row_up_to_the_limit_asked_for() -> Result<()> {
    let pool = test_pool().await?;
    let t = tenant();
    let kept: Vec<usize> = (0..12_000).collect();
    let rows = fake_rows(&t, 0, [7u8; 32], &kept);
    db::ledger::insert_rows(&pool, &rows).await?;
    let since = chrono::Utc::now() - chrono::Duration::hours(1);
    let until = chrono::Utc::now() + chrono::Duration::hours(1);
    let got = db::ledger::read_rows_in_window(&pool, &t, since, until, None, 50_000).await?;
    assert_eq!(
        got.len(),
        12_000,
        "asked for 50,000 of 12,000 rows — a smaller private cap TRUNCATES the export"
    );
    assert_eq!(got.last().map(|r| r.seq), Some(11_999));
    let range = db::ledger::ledger_range(&pool, &t).await?;
    assert_eq!(
        (range.from, range.to, range.total),
        (Some(0), Some(11_999), 12_000)
    );
    Ok(())
}

// ── B-383 (f): the negative auth cache ────────────────────────────────────
//
// An unknown `tlane_` key used to cost one Neon round trip PER ATTEMPT; a scan of
// random keys was a scan of Postgres. Now a miss is remembered for 30 s: the second
// probe of the same unknown key answers from the negative cache (the counter moves,
// the pool is not asked), and a key MINTED after a probe authenticates at once
// because `create` forgets the negative entry.

#[tokio::test]
#[ignore]
async fn b383_negative_cache_absorbs_repeat_misses_and_a_mint_clears_it() -> Result<()> {
    use std::sync::atomic::Ordering;
    let pool = test_pool().await?;
    let _ = db::api_keys::init_pepper(&"11".repeat(32));
    let key_body = format!("probe_before_mint_{}", Uuid::new_v4().simple());

    let first = db::api_keys::lookup_tenant_by_key_body(&pool, &key_body).await?;
    assert!(first.is_none(), "unknown key is unknown");
    let neg_before = db::api_keys::AUTH_NEGATIVE_HIT_TOTAL.load(Ordering::Relaxed);
    let second = db::api_keys::lookup_tenant_by_key_body(&pool, &key_body).await?;
    assert!(second.is_none());
    assert_eq!(
        db::api_keys::AUTH_NEGATIVE_HIT_TOTAL.load(Ordering::Relaxed),
        neg_before + 1,
        "the second probe of an unknown key must be answered by the negative cache"
    );

    // Mint that exact key now: it must authenticate immediately, not in 30 s.
    let tenant_id = Uuid::new_v4();
    db::tenants::create(&pool, tenant_id, "neg-cache-tenant", "free").await?;
    let material = db::api_keys::KeyMaterial::from_body(&key_body)?;
    db::api_keys::create(
        &pool,
        &tracelane_shared::TenantId::from_jwt_claim(tenant_id),
        &material,
        "ci-neg-cache",
        &key_body[..6],
        None,
        &db::api_keys::MintOptions::default(),
    )
    .await?;
    let after_mint = db::api_keys::lookup_tenant_by_key_body(&pool, &key_body).await?;
    assert!(
        after_mint.is_some(),
        "a key minted after being probed must authenticate at once (the mint forgets the negative entry)"
    );
    Ok(())
}

/// B-383 (a): a row sealed under KEK 0 is re-wrapped under KEK 1 by
/// `byok-rotate`, reads back under a ring holding KEK 1, and FAILS under a ring
/// holding only KEK 0 — the property that makes dropping the old key safe. Also:
/// dry-run moves nothing; a second execute run finds nothing to do; the audit
/// key columns move too; a row whose blob changed underneath is left alone.
#[tokio::test]
#[ignore]
async fn b383_byok_rotate_rewraps_every_blob_under_the_active_kek() -> Result<()> {
    use base64::Engine as _;
    use secrecy::{ExposeSecret as _, SecretString};
    let pool = test_pool().await?;
    let tenant_id = Uuid::new_v4();
    let _tenant = db::tenants::create(&pool, tenant_id, "b383-rotate", "free").await?;
    let tenant = tracelane_shared::TenantId::from_jwt_claim(tenant_id);
    let k0 = base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]);
    let k1 = base64::engine::general_purpose::STANDARD.encode([0x22u8; 32]);

    // Today's process: one legacy key, writing v2.
    let legacy = byok::ByokMasterKey::from_values(Some(&k0), None, None)?.expect("ring");
    let secret = SecretString::from("sk-live-provider-key-do-not-use".to_string());
    let v2 = legacy.encrypt_with_context(&secret, &byok::provider_key_aad(&tenant, "openai"))?;
    db::provider_keys::upsert(
        &pool,
        &tenant,
        "openai",
        "default",
        &v2,
        "tuse",
        &db::control_audit::Actor::system("test"),
    )
    .await?;
    let audit_secret = SecretString::from("pkcs8-der-b64-do-not-use".to_string());
    let audit_v2 = legacy.encrypt_with_context(&audit_secret, &byok::audit_key_aad(&tenant))?;
    let anchor_v2 = legacy.encrypt_with_context(&audit_secret, &byok::anchor_key_aad(&tenant))?;
    {
        let c = pool.get().await?;
        c.execute(
            "INSERT INTO tenant_audit_keys (tenant_id, encrypted_private_key, public_key_b64, encrypted_anchor_key) \
             VALUES ($1, $2, '', $3)",
            &[&tenant_id, &audit_v2, &anchor_v2],
        )
        .await?;
    }

    // The custom-hook credential participates in the same re-wrap operation.
    let hook_id = Uuid::new_v4();
    let endpoint = "https://hooks.example.com/check";
    let hook_aad = byok::guardrail_hook_aad(&tenant_id, &format!("{hook_id}:{endpoint}"));
    let hook_v2 = legacy.encrypt_with_context(&secret, &hook_aad)?;
    pool.get().await?.execute(
        "INSERT INTO guardrail_hooks (tenant_id,id,config,ciphertext_b64,updated_by) VALUES ($1,$2,$3,$4,'test')",
        &[&tenant_id,&hook_id,&serde_json::json!({"endpoint":endpoint,"pre":true,"post":false,"timeout_ms":1000}),&hook_v2],
    ).await?;

    // The rotated process: both keys, KEK 1 active.
    let ring = byok::ByokMasterKey::from_values(Some(&k0), Some(&format!("1:{k1}")), Some(1))?
        .expect("ring");
    assert_eq!(ring.active_kek(), 1);

    // Dry run: reports, writes nothing.
    let dry = byok_rotate::rotate(&pool, &ring, true).await?;
    assert_eq!(
        dry.tables.iter().map(|t| t.rewrapped).sum::<u64>(),
        4,
        "{}",
        dry.render()
    );
    assert_eq!(dry.remaining(), 4);
    let still_v2 = db::provider_keys::get(&pool, &tenant, "openai", "default")
        .await?
        .expect("row");
    assert_eq!(still_v2.ciphertext_b64, v2, "dry-run must not write");

    // Execute.
    let run = byok_rotate::rotate(&pool, &ring, false).await?;
    assert_eq!(run.failed(), 0, "{}", run.render());
    assert_eq!(run.remaining(), 0, "{}", run.render());
    assert_eq!(
        run.tables.iter().map(|t| t.rewrapped).sum::<u64>(),
        4,
        "{}",
        run.render()
    );

    // The row is now v3 under KEK 1, decrypts under the ring, and NOT under KEK 0 alone.
    let moved = db::provider_keys::get(&pool, &tenant, "openai", "default")
        .await?
        .expect("row");
    assert_ne!(moved.ciphertext_b64, v2);
    assert_eq!(
        byok::ByokMasterKey::kek_id_of(&moved.ciphertext_b64),
        Some(1)
    );
    let aad = byok::provider_key_aad(&tenant, "openai");
    assert_eq!(
        ring.decrypt_with_context(&moved.ciphertext_b64, &aad)?
            .expose_secret(),
        secret.expose_secret()
    );
    let err = legacy
        .decrypt_with_context(&moved.ciphertext_b64, &aad)
        .unwrap_err()
        .to_string();
    assert!(err.contains("sealed under KEK 1"), "{err}");
    // The audit columns moved too, and still open under their own AADs.
    {
        let c = pool.get().await?;
        let row = c
            .query_one(
                "SELECT encrypted_private_key, encrypted_anchor_key FROM tenant_audit_keys WHERE tenant_id = $1",
                &[&tenant_id],
            )
            .await?;
        let pk: String = row.get(0);
        let ak: String = row.get(1);
        assert_eq!(byok::ByokMasterKey::kek_id_of(&pk), Some(1));
        assert_eq!(byok::ByokMasterKey::kek_id_of(&ak), Some(1));
        assert_eq!(
            ring.decrypt_with_context(&pk, &byok::audit_key_aad(&tenant))?
                .expose_secret(),
            audit_secret.expose_secret()
        );
        assert_eq!(
            ring.decrypt_with_context(&ak, &byok::anchor_key_aad(&tenant))?
                .expose_secret(),
            audit_secret.expose_secret()
        );
    }
    let hook_moved: String = pool
        .get()
        .await?
        .query_one(
            "SELECT ciphertext_b64 FROM guardrail_hooks WHERE tenant_id = $1 AND id = $2",
            &[&tenant_id, &hook_id],
        )
        .await?
        .get(0);
    assert_ne!(hook_moved, hook_v2);
    assert_eq!(byok::ByokMasterKey::kek_id_of(&hook_moved), Some(1));
    assert_eq!(
        ring.decrypt_with_context(&hook_moved, &hook_aad)?
            .expose_secret(),
        secret.expose_secret()
    );
    // Idempotent: a second run has nothing to do.
    let again = byok_rotate::rotate(&pool, &ring, false).await?;
    assert_eq!(
        again.tables.iter().map(|t| t.rewrapped).sum::<u64>(),
        0,
        "{}",
        again.render()
    );
    assert_eq!(again.tables.iter().map(|t| t.current).sum::<u64>(), 4);

    // A blob the ring cannot open is reported, not skipped silently, and does
    // not stop the other rows.
    let stranger = byok::ByokMasterKey::from_values(
        Some(&base64::engine::general_purpose::STANDARD.encode([0x33u8; 32])),
        None,
        None,
    )?
    .expect("ring");
    let foreign =
        stranger.encrypt_with_context(&secret, &byok::provider_key_aad(&tenant, "cohere"))?;
    db::provider_keys::upsert(
        &pool,
        &tenant,
        "cohere",
        "default",
        &foreign,
        "tuse",
        &db::control_audit::Actor::system("test"),
    )
    .await?;
    let with_foreign = byok_rotate::rotate(&pool, &ring, false).await?;
    assert_eq!(with_foreign.failed(), 1, "{}", with_foreign.render());
    assert_eq!(
        with_foreign
            .tables
            .iter()
            .find(|t| t.table == "provider_keys")
            .unwrap()
            .unreadable,
        1
    );
    Ok(())
}

/// B-386 (a): the single-instance lock. A second session cannot take it while
/// the first holds it; dropping the holder releases it (session-scoped, so a
/// crash releases it too — no lease, no stale file).
#[tokio::test]
#[ignore]
async fn b386_singleton_lock_admits_one_holder_and_releases_on_drop() -> Result<()> {
    let _pool = test_pool().await?;
    // The lock is per Postgres *server* (hashtext of a constant), so the test
    // database created by `test_pool` is irrelevant — point at the admin URL.
    let cfg: tokio_postgres::Config = require_url().parse()?;
    let first = db::singleton::try_acquire(&cfg).await?;
    assert!(first.is_some(), "first holder takes the lock");
    let second = db::singleton::try_acquire(&cfg).await?;
    assert!(
        second.is_none(),
        "a second gateway must be refused while the first holds it"
    );
    drop(first);
    // Release is asynchronous (the session has to close); poll rather than sleep-and-hope.
    let mut reacquired = None;
    for _ in 0..50 {
        if let Some(l) = db::singleton::try_acquire(&cfg).await? {
            reacquired = Some(l);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(
        reacquired.is_some(),
        "dropping the holder must release the lock"
    );
    Ok(())
}

/// RI-04 proof 2 — the per-job claim admits exactly one of two claimants on the
/// same job name and releases when the winner's transaction is dropped. The
/// winner's `Won(tx)` is held OPEN across the second claim, which is the exact
/// condition under test; the loser must read `Lost`, never `CannotTell` (that
/// would be the test's own Postgres breaking, not the property).
#[tokio::test]
#[ignore]
async fn ri04_job_guard_admits_exactly_one_claimant_and_releases_on_drop() -> Result<()> {
    let pool = test_pool().await?;
    let mut client_a = pool.get().await?;
    let mut client_b = pool.get().await?;

    let claim_a = db::job_guard::claim(&mut client_a, "job:test").await;
    let claim_b = db::job_guard::claim(&mut client_b, "job:test").await;
    let winner_tx = match (claim_a, claim_b) {
        (db::job_guard::Claim::Won(tx), db::job_guard::Claim::Lost)
        | (db::job_guard::Claim::Lost, db::job_guard::Claim::Won(tx)) => tx,
        _ => panic!("expected exactly one Won and one Lost for the same job claimed concurrently"),
    };
    // The real release path at every call site: nothing is written through the
    // transaction, so a bare drop (ROLLBACK) is what releases the xact lock.
    drop(winner_tx);

    let mut client_c = pool.get().await?;
    let mut reacquired = false;
    for _ in 0..50 {
        match db::job_guard::claim(&mut client_c, "job:test").await {
            db::job_guard::Claim::Won(tx2) => {
                reacquired = true;
                drop(tx2);
                break;
            }
            db::job_guard::Claim::Lost => {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            db::job_guard::Claim::CannotTell => {
                panic!("claim probe failed against the test Postgres")
            }
        }
    }
    assert!(
        reacquired,
        "dropping the winner's transaction must release the transaction-scoped advisory lock"
    );
    Ok(())
}

/// RI-04 proof 3 (the guard's half — the spec's full version doubles a metering
/// run against ClickHouse and is designed in `specs/RI-04 §7`): two processes'
/// worth of `run_claimed` on the SAME job, started together, run the body exactly
/// ONCE; a third, after both have finished, runs again. Without the guard the
/// counter reads 2 — that is the RED this pins.
#[tokio::test]
#[ignore]
async fn ri04_run_claimed_runs_a_job_once_across_two_concurrent_runners() -> Result<()> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let pool = test_pool().await?;
    let ran = Arc::new(AtomicUsize::new(0));
    let body = |ran: Arc<AtomicUsize>| async move {
        ran.fetch_add(1, Ordering::SeqCst);
        // Hold the claim long enough for the other runner to attempt its own.
        // 400 ms flaked under a loaded full gate (2026-09-24: the second runner
        // was scheduled after the first had released, so the body ran twice and
        // the test read 2 — green 22/22 when re-run alone). 3 s is still a short
        // test and leaves the race no room on a busy box.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    };
    let (a, b) = tokio::join!(
        db::job_guard::run_claimed(&pool, "job:once", || body(Arc::clone(&ran))),
        db::job_guard::run_claimed(&pool, "job:once", || body(Arc::clone(&ran))),
    );
    assert_eq!(
        ran.load(Ordering::SeqCst),
        1,
        "two concurrent runners must run the job body exactly once"
    );
    assert!(a.is_some() ^ b.is_some(), "exactly one runner reports Some");
    // Both done → the lock is free → the next cadence runs.
    let c = db::job_guard::run_claimed(&pool, "job:once", || body(Arc::clone(&ran))).await;
    assert!(
        c.is_some(),
        "a fresh claim after both runners finished must win"
    );
    assert_eq!(ran.load(Ordering::SeqCst), 2);
    Ok(())
}

// ── B-594 (2026-10-03): a flood of NEVER-SEEN keys is bounded at Postgres ──
//
// The negative cache above absorbs REPEATS; a new random key per request
// defeats it by construction. The cold-lookup gate (`db::api_keys::
// gated_cold_lookup`, scoped per request by `preauth_limiter::layer`) reserves
// a token per source before `pool.get()`. Measured here at the DATABASE, not at
// a fake: the scans Postgres itself counted on `api_keys` (index + sequential,
// read from `pg_stat_user_tables` after the flooding connections closed, which
// flushes their statistics) stay within the bucket, while a warm valid key from
// the same source and a junk key from another source behave normally.

/// A fixed-size, non-refilling bucket per source, enough to prove placement:
/// the production limiter (token bucket, IPv6 /64, overflow) is unit-tested in
/// `preauth_limiter.rs`, which this crate cannot mount.
struct FixedGate {
    burst: u32,
    taken: std::sync::Mutex<std::collections::HashMap<u128, u32>>,
}

impl db::api_keys::ColdLookupGate for FixedGate {
    fn try_acquire(&self, source: u128) -> std::result::Result<db::api_keys::Reservation, u64> {
        let mut m = self.taken.lock().unwrap();
        let n = m.entry(source).or_insert(0);
        if *n >= self.burst {
            return Err(1);
        }
        *n += 1;
        Ok(db::api_keys::Reservation::default())
    }
    fn refund(&self, source: u128, _reservation: db::api_keys::Reservation) {
        let mut m = self.taken.lock().unwrap();
        if let Some(n) = m.get_mut(&source) {
            *n = n.saturating_sub(1);
        }
    }
    fn charge(&self, _source: u128) {}
}

async fn api_keys_scans(db_name: &str) -> Result<i64> {
    let mut cfg: tokio_postgres::Config = require_url().parse()?;
    cfg.dbname(db_name);
    let (client, conn) = cfg.connect(tokio_postgres::NoTls).await?;
    let handle = tokio::spawn(conn);
    // A closing backend flushes its counters as it exits; poll until two reads
    // a beat apart agree, so the figure is settled rather than mid-flush.
    let read = || async {
        client
            .batch_execute("SELECT pg_stat_clear_snapshot()")
            .await?;
        let row = client
            .query_one(
                "SELECT COALESCE(idx_scan, 0) + COALESCE(seq_scan, 0) \
                 FROM pg_stat_user_tables WHERE relname = 'api_keys'",
                &[],
            )
            .await?;
        anyhow::Ok(row.get::<_, i64>(0))
    };
    let mut last = read().await?;
    for _ in 0..40 {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let now = read().await?;
        if now == last {
            break;
        }
        last = now;
    }
    drop(client);
    handle.abort();
    Ok(last)
}

#[tokio::test]
#[ignore]
async fn b594_a_flood_of_never_seen_keys_is_bounded_at_postgres() -> Result<()> {
    use std::sync::Arc;
    let template = template_database().await?;
    let db_name = create_fresh_database(Some(template)).await?;
    let _ = db::api_keys::init_pepper(&"11".repeat(32));

    // A real key, minted and warmed on its own pool (not counted below).
    let warm_body = format!("b594_warm_{}", Uuid::new_v4().simple());
    {
        let pool = pool_for(&db_name)?;
        let tenant_id = Uuid::new_v4();
        db::tenants::create(&pool, tenant_id, "b594-tenant", "free").await?;
        let material = db::api_keys::KeyMaterial::from_body(&warm_body)?;
        db::api_keys::create(
            &pool,
            &tracelane_shared::TenantId::from_jwt_claim(tenant_id),
            &material,
            "ci-b594",
            &warm_body[..6],
            None,
            &db::api_keys::MintOptions::default(),
        )
        .await?;
        assert!(
            db::api_keys::lookup_tenant_by_key_body(&pool, &warm_body)
                .await?
                .is_some()
        );
        pool.close();
    }
    let before = api_keys_scans(&db_name).await?;

    const BURST: u32 = 10;
    const FLOOD: usize = 300;
    let gate: Arc<dyn db::api_keys::ColdLookupGate> = Arc::new(FixedGate {
        burst: BURST,
        taken: std::sync::Mutex::new(std::collections::HashMap::new()),
    });
    let scope = |source: u128| db::api_keys::ColdGateScope::new(Arc::clone(&gate), source, None);
    let pool = pool_for(&db_name)?;
    let (mut refused, mut not_found) = (0usize, 0usize);
    for i in 0..FLOOD {
        let body = format!("b594_junk_{i}_{}", Uuid::new_v4().simple());
        match db::api_keys::with_cold_gate(
            scope(1),
            db::api_keys::lookup_tenant_by_key_body(&pool, &body),
        )
        .await
        {
            Ok(None) => not_found += 1,
            Ok(Some(_)) => panic!("a random key authenticated"),
            Err(e) if e.is::<db::api_keys::AuthThrottled>() => refused += 1,
            Err(e) => return Err(e),
        }
    }
    assert_eq!(
        not_found, BURST as usize,
        "exactly the burst reached the store"
    );
    assert_eq!(refused, FLOOD - BURST as usize);

    // The warm valid key, same source, after the flood: served.
    let warm = db::api_keys::with_cold_gate(
        scope(1),
        db::api_keys::lookup_tenant_by_key_body(&pool, &warm_body),
    )
    .await?;
    assert!(
        warm.is_some(),
        "a warm valid key must not pay for the flood"
    );
    // Another source still reaches the store.
    let other = db::api_keys::with_cold_gate(
        scope(2),
        db::api_keys::lookup_tenant_by_key_body(&pool, "b594_other_source_junk_key"),
    )
    .await?;
    assert!(other.is_none());
    pool.close();

    let delta = api_keys_scans(&db_name).await? - before;
    eprintln!(
        "B-594 real-Postgres: {FLOOD} junk keys + 1 other-source key -> {delta} api_keys scans"
    );
    // Exactly the admitted lookups: fewer would mean the measurement sees nothing,
    // more would mean a refused key still reached Postgres.
    assert_eq!(
        delta,
        i64::from(BURST) + 1,
        "{FLOOD} never-seen keys + 1 other-source key cost {delta} api_keys scans; the gate admits {}",
        BURST + 1
    );
    Ok(())
}

// ── rev4 H1 d / M1 (2026-10-03): the VALID-KEY SET, against a real Postgres ──
//
// A flood of never-seen keys does ZERO per-key lookups once the set is loaded —
// the only `api_keys` scans it causes are the set's own reads (one for everyone,
// at most once per refresh); a key minted elsewhere (here: by `create`, which does
// not touch THIS set) is accepted on its first request within one refresh; a key
// revoked after the set loaded is refused by the ordinary lookup it is admitted to.
// The set is this test's OWN instance over its own database (the process set would
// answer for another database).

#[tokio::test]
#[ignore]
async fn b594_rev4_the_valid_key_set_refuses_junk_without_a_lookup_and_tracks_mints_and_revokes()
-> Result<()> {
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};
    let template = template_database().await?;
    let db_name = create_fresh_database(Some(template)).await?;
    let _ = db::api_keys::init_pepper(&"11".repeat(32));
    let tenant_id = Uuid::new_v4();
    let tenant = tracelane_shared::TenantId::from_jwt_claim(tenant_id);
    {
        let pool = pool_for(&db_name)?;
        db::tenants::create(&pool, tenant_id, "rev4-known-keys", "free").await?;
        pool.close();
    }
    let mint = |body: String| {
        let tenant = tenant.clone();
        let db_name = db_name.clone();
        async move {
            let pool = pool_for(&db_name)?;
            let material = db::api_keys::KeyMaterial::from_body(&body)?;
            let k = db::api_keys::create(
                &pool,
                &tenant,
                &material,
                "ci-rev4",
                &body[..6],
                None,
                &db::api_keys::MintOptions::default(),
            )
            .await?;
            pool.close();
            anyhow::Ok(k.id)
        }
    };
    // Key A exists before the set loads; it is revoked AFTER (never looked up
    // before that, so no positive-cache entry can answer for it).
    let body_a = format!("rev4_a_{}", Uuid::new_v4().simple());
    let id_a = mint(body_a.clone()).await?;

    const REFRESH: Duration = Duration::from_millis(300);
    let known = db::api_keys::KnownKeys::new(db::api_keys::KnownKeysConfig {
        refresh: REFRESH,
        wait: Duration::from_secs(5),
        full_reload: Duration::from_secs(3600),
        overlap: Duration::from_secs(300),
        max: 10_000,
    });

    // 1. The flood: 300 never-seen keys at once.
    let before = api_keys_scans(&db_name).await?;
    let reads_before = db::api_keys::KNOWN_KEYS_READS_TOTAL.load(Ordering::SeqCst);
    {
        let pool = pool_for(&db_name)?;
        let flood =
            (0..300).map(|i| {
                let body = format!("rev4_junk_{i}_{}", Uuid::new_v4().simple());
                let (pool, known) = (&pool, &known);
                async move {
                    db::api_keys::lookup_tenant_by_key_body_with(pool, &body, Some(known)).await
                }
            });
        for r in futures::future::join_all(flood).await {
            assert!(r?.is_none(), "a random key authenticated");
        }
        pool.close();
    }
    assert!(known.is_loaded(), "the first miss loaded the set");
    let reads = db::api_keys::KNOWN_KEYS_READS_TOTAL.load(Ordering::SeqCst) - reads_before;
    let scans = api_keys_scans(&db_name).await? - before;
    eprintln!("rev4 real-Postgres: 300 junk keys -> {reads} set reads, {scans} api_keys scans");
    assert!(
        (1..=3).contains(&reads),
        "one load plus at most a refresh or two for everyone, got {reads}"
    );
    assert_eq!(
        scans,
        i64::try_from(reads)?,
        "every api_keys scan is a set read — zero per-key lookups for 300 junk keys"
    );

    // 2. A key minted elsewhere after the set loaded: accepted on its first request,
    //    within one refresh.
    let body_b = format!("rev4_b_{}", Uuid::new_v4().simple());
    mint(body_b.clone()).await?;
    let pool = pool_for(&db_name)?;
    let t0 = Instant::now();
    let b = db::api_keys::lookup_tenant_by_key_body_with(&pool, &body_b, Some(&known)).await?;
    let waited = t0.elapsed();
    assert!(
        b.is_some(),
        "a freshly minted key must authenticate on its first request"
    );
    assert!(
        waited < REFRESH + Duration::from_secs(2),
        "accepted after {waited:?}; the bound is one refresh plus one query"
    );

    // 3. Key A, revoked after the set loaded: still in the set, refused by the
    //    lookup the set admits it to.
    db::api_keys::revoke(&pool, id_a).await?;
    let a = db::api_keys::lookup_tenant_by_key_body_with(&pool, &body_a, Some(&known)).await?;
    assert!(a.is_none(), "a revoked key must be refused");
    pool.close();
    Ok(())
}

// ── OG-23 / OG-20: projects, assignment and the auth JOIN, on a real Postgres ──────────

/// A fresh tenant + the pepper, for the OG-23/OG-20 tests.
async fn og23_tenant(
    pool: &deadpool_postgres::Pool,
    name: &str,
) -> Result<tracelane_shared::TenantId> {
    let id = Uuid::new_v4();
    db::tenants::create(pool, id, name, "free").await?;
    let _ = db::api_keys::init_pepper(&"11".repeat(32));
    Ok(tracelane_shared::TenantId::from_jwt_claim(id))
}

fn og23_new(name: &str, policy: Option<serde_json::Value>) -> db::projects::NewProject {
    db::projects::NewProject {
        name: name.into(),
        environments: vec!["production".into(), "staging".into()],
        policy,
    }
}

/// OG-23 proof 1 + 3, OG-20 proof 7: a key minted into a project authenticates with the
/// project, its environment and BOTH policy layers on its claims — cold, and again after a
/// project-policy edit (which evicts the key, so the next lookup reads the new policy).
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn og23_a_project_keys_auth_carries_project_environment_and_both_policies() -> Result<()> {
    use db::api_keys::*;
    use db::projects::{CreateOutcome, PatchOutcome, ProjectPatch};
    let pool = test_pool().await?;
    let tenant = og23_tenant(&pool, "og23-auth").await?;
    let project_policy = serde_json::json!({"models": {"allow": ["gpt-4o*"]}});
    let CreateOutcome::Created(project) = db::projects::create(
        &pool,
        &tenant,
        &og23_new("Checkout", Some(project_policy.clone())),
        100,
        "owner-a",
    )
    .await?
    else {
        panic!("project create refused")
    };
    let key_policy = serde_json::json!({"source_ips": ["10.0.0.0/8"]});
    let key = mint(
        &pool,
        &tenant,
        "checkout-staging",
        Some("owner-a"),
        MintOptions {
            scope: Some(vec!["chat".into()]),
            project_id: Some(project.id),
            environment: Some("staging".into()),
            policy: Some(key_policy.clone()),
            ..Default::default()
        },
    )
    .await?;
    let body = key.raw_key.strip_prefix("tlane_").unwrap();
    let auth = lookup_tenant_by_key_body(&pool, body)
        .await?
        .expect("authenticates");
    let gov = auth.governance.expect("a governance");
    assert_eq!(gov.project_id, Some(project.id));
    assert_eq!(gov.environment.as_deref(), Some("staging"));
    assert_eq!(gov.layers.len(), 2, "the project's policy AND the key's");
    assert!(gov.has_policy());
    // Edit the PROJECT's policy: the key is evicted, so its next lookup reads the new one.
    let PatchOutcome::Updated { changed, .. } = db::projects::update(
        &pool,
        &tenant,
        project.id,
        &ProjectPatch {
            policy: Some(None),
            ..Default::default()
        },
        "owner-a",
    )
    .await?
    else {
        panic!("project update refused")
    };
    assert_eq!(changed, vec!["policy"]);
    let auth = lookup_tenant_by_key_body(&pool, body)
        .await?
        .expect("authenticates");
    assert_eq!(auth.governance.expect("still a project").layers.len(), 1);
    // A key with nothing set carries no governance at all (today's shape).
    let plain = mint(&pool, &tenant, "plain", None, MintOptions::default()).await?;
    let auth = lookup_tenant_by_key_body(&pool, plain.raw_key.strip_prefix("tlane_").unwrap())
        .await?
        .expect("authenticates");
    assert!(auth.governance.is_none());
    // The audit rows exist, before AND after for the policy change.
    let client = pool.get().await?;
    let n: i64 = client
        .query_one(
            "SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id = $1 \
             AND action IN ('project.create', 'project.update')",
            &[tenant.as_uuid()],
        )
        .await?
        .get(0);
    assert_eq!(n, 2);
    Ok(())
}

/// OG-23 proof 2 — the guard blocks: tenant B can neither read, edit, archive nor attach
/// a key to tenant A's project; every answer is the one an absent project gets.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn og23_another_tenants_project_is_unreachable() -> Result<()> {
    use db::api_keys::*;
    use db::projects::{ArchiveOutcome, CreateOutcome, PatchOutcome, ProjectPatch};
    let pool = test_pool().await?;
    let a = og23_tenant(&pool, "og23-a").await?;
    let b = og23_tenant(&pool, "og23-b").await?;
    let CreateOutcome::Created(pa) =
        db::projects::create(&pool, &a, &og23_new("A", None), 100, "owner-a").await?
    else {
        panic!("create refused")
    };
    assert!(db::projects::get(&pool, &b, pa.id).await?.is_none());
    assert!(db::projects::list(&pool, &b).await?.is_empty());
    assert_eq!(
        db::projects::update(
            &pool,
            &b,
            pa.id,
            &ProjectPatch {
                name: Some("stolen".into()),
                ..Default::default()
            },
            "owner-b"
        )
        .await?,
        PatchOutcome::NotFound
    );
    assert_eq!(
        db::projects::archive(&pool, &b, pa.id, "owner-b").await?,
        ArchiveOutcome::NotFound
    );
    // Mint INTO A's project as B: refused, nothing minted.
    let err = mint(
        &pool,
        &b,
        "k",
        None,
        MintOptions {
            project_id: Some(pa.id),
            ..Default::default()
        },
    )
    .await
    .expect_err("must be refused");
    assert!(matches!(
        err.downcast_ref::<AssignmentError>(),
        Some(AssignmentError::ProjectNotFound)
    ));
    // Move B's own key into A's project: refused under the row lock, row unchanged.
    let kb = mint(&pool, &b, "kb", None, MintOptions::default()).await?;
    let out = db::api_keys::update(
        &pool,
        &b,
        kb.api_key.id,
        KeyEditor::Any,
        &KeyPatch {
            project_id: Some(Some(pa.id)),
            ..Default::default()
        },
        "owner-b",
    )
    .await?;
    assert_eq!(out, UpdateOutcome::ProjectNotFound);
    assert_eq!(
        db::api_keys::get(&pool, &b, kb.api_key.id)
            .await?
            .unwrap()
            .project_id,
        None
    );
    // A's project is untouched.
    assert_eq!(
        db::projects::get(&pool, &a, pa.id).await?.unwrap().0.name,
        "A"
    );
    Ok(())
}

/// OG-23 §4: assignment and archive refusals, and rotation keeps the governance.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn og23_assignment_archive_and_rotation_rules() -> Result<()> {
    use db::api_keys::*;
    use db::projects::{ArchiveOutcome, CreateOutcome, PatchOutcome, ProjectPatch};
    let pool = test_pool().await?;
    let t = og23_tenant(&pool, "og23-rules").await?;
    let CreateOutcome::Created(p) =
        db::projects::create(&pool, &t, &og23_new("P", None), 2, "owner").await?
    else {
        panic!("create refused")
    };
    assert_eq!(
        db::projects::create(&pool, &t, &og23_new("p", None), 2, "owner").await?,
        CreateOutcome::NameTaken,
        "names are unique per tenant, case-insensitively"
    );
    let CreateOutcome::Created(_) =
        db::projects::create(&pool, &t, &og23_new("Q", None), 2, "owner").await?
    else {
        panic!("second create refused")
    };
    assert_eq!(
        db::projects::create(&pool, &t, &og23_new("R", None), 2, "owner").await?,
        CreateOutcome::LimitReached { max: 2 }
    );
    // An environment the project does not have, and an environment with no project.
    let err = mint(
        &pool,
        &t,
        "k",
        None,
        MintOptions {
            project_id: Some(p.id),
            environment: Some("qa".into()),
            ..Default::default()
        },
    )
    .await
    .expect_err("qa is not one of P's environments");
    assert!(matches!(
        err.downcast_ref::<AssignmentError>(),
        Some(AssignmentError::EnvironmentNotInProject(_))
    ));
    let policy = serde_json::json!({"max_output_tokens": 100});
    let k = mint(
        &pool,
        &t,
        "k",
        Some("owner"),
        MintOptions {
            scope: Some(vec!["chat".into()]),
            project_id: Some(p.id),
            environment: Some("staging".into()),
            policy: Some(policy.clone()),
            ..Default::default()
        },
    )
    .await?;
    // Clearing the project while the key keeps its environment is refused.
    assert_eq!(
        db::api_keys::update(
            &pool,
            &t,
            k.api_key.id,
            KeyEditor::Any,
            &KeyPatch {
                project_id: Some(None),
                ..Default::default()
            },
            "owner"
        )
        .await?,
        UpdateOutcome::EnvironmentNeedsProject
    );
    // Removing an environment a live key carries is refused.
    assert_eq!(
        db::projects::update(
            &pool,
            &t,
            p.id,
            &ProjectPatch {
                environments: Some(vec!["production".into()]),
                ..Default::default()
            },
            "owner"
        )
        .await?,
        PatchOutcome::EnvironmentInUse {
            environment: "staging".into()
        }
    );
    // Archive refused while the key is live.
    assert_eq!(
        db::projects::archive(&pool, &t, p.id, "owner").await?,
        ArchiveOutcome::HasKeys { count: 1 }
    );
    // Rotation: the successor carries project, environment AND policy.
    let rotated = rotate(&pool, &t, k.api_key.id, "owner", 0).await?.unwrap();
    assert_eq!(rotated.options.project_id, Some(p.id));
    assert_eq!(rotated.options.environment.as_deref(), Some("staging"));
    assert_eq!(rotated.options.policy, Some(policy));
    let succ = rotated
        .minted
        .raw_key
        .strip_prefix("tlane_")
        .unwrap()
        .to_owned();
    let auth = lookup_tenant_by_key_body(&pool, &succ)
        .await?
        .expect("successor works");
    assert_eq!(auth.governance.expect("governed").layers.len(), 1);
    // Revoke the successor; then nothing live remains and the archive succeeds.
    assert!(
        revoke_key(&pool, &t, rotated.minted.api_key.id, "owner")
            .await?
            .is_some()
    );
    assert_eq!(
        db::projects::archive(&pool, &t, p.id, "owner").await?,
        ArchiveOutcome::Archived
    );
    assert!(
        db::projects::get(&pool, &t, p.id).await?.is_none(),
        "archived is not live"
    );
    Ok(())
}

/// OG-20 §2: a stored policy the gateway cannot parse is an INVALID layer on the auth
/// result — refused downstream, never read as "no policy". (The write path validates, so
/// this state needs a hand edit; the CHECK still requires an object.)
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn og20_a_hand_edited_unparseable_policy_authenticates_as_an_invalid_layer() -> Result<()> {
    use db::api_keys::*;
    let pool = test_pool().await?;
    let t = og23_tenant(&pool, "og20-invalid").await?;
    let k = mint(&pool, &t, "k", None, MintOptions::default()).await?;
    let client = pool.get().await?;
    assert!(
        client
            .execute(
                "UPDATE api_keys SET policy = '\"a string\"'::jsonb WHERE id = $1",
                &[&k.api_key.id]
            )
            .await
            .is_err(),
        "the CHECK refuses a non-object"
    );
    client
        .execute(
            "UPDATE api_keys SET policy = '{\"rule_from_the_future\": true}'::jsonb WHERE id = $1",
            &[&k.api_key.id],
        )
        .await?;
    let auth = lookup_tenant_by_key_body(&pool, k.raw_key.strip_prefix("tlane_").unwrap())
        .await?
        .expect("the credential itself is good");
    let gov = auth.governance.expect("a governance");
    assert_eq!(
        gov.layers[0].policy,
        tracelane_shared::key_policy::LayerPolicy::Invalid
    );
    assert_eq!(
        gov.check_source(Some("10.0.0.1".parse().unwrap()))
            .unwrap_err()
            .code,
        "policy_invalid"
    );
    Ok(())
}

// ── OG-25 / OG-24: workspace controls, revoke-all and the alert outbox, on a real Postgres ──

/// OG-25 proof 4: revoke-all revokes every live key of ONE tenant in one transaction,
/// writes one `api_key.revoke_all` row per call, and leaves another tenant untouched; a
/// revoked key no longer authenticates.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn og25_revoke_all_revokes_every_key_of_one_tenant_only() -> Result<()> {
    use db::api_keys::*;
    let pool = test_pool().await?;
    let a = og23_tenant(&pool, "og25-a").await?;
    let b = og23_tenant(&pool, "og25-b").await?;
    let k1 = mint(&pool, &a, "a1", None, MintOptions::default()).await?;
    let _k2 = mint(&pool, &a, "a2", None, MintOptions::default()).await?;
    let kb = mint(&pool, &b, "b1", None, MintOptions::default()).await?;
    let ids = revoke_all_keys(&pool, &a, "owner-a").await?;
    assert_eq!(ids.len(), 2);
    assert!(
        lookup_tenant_by_key_body(&pool, k1.raw_key.strip_prefix("tlane_").unwrap())
            .await?
            .is_none(),
        "a revoked key no longer authenticates"
    );
    assert!(
        lookup_tenant_by_key_body(&pool, kb.raw_key.strip_prefix("tlane_").unwrap())
            .await?
            .is_some(),
        "the other tenant's key is untouched"
    );
    assert!(
        revoke_all_keys(&pool, &a, "owner-a").await?.is_empty(),
        "nothing left to revoke"
    );
    let client = pool.get().await?;
    let n: i64 = client
        .query_one(
            "SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id = $1 \
             AND action = 'api_key.revoke_all'",
            &[a.as_uuid()],
        )
        .await?
        .get(0);
    assert_eq!(n, 2, "one control-change row per call");
    Ok(())
}

/// OG-25: the controls row round-trips through pause (idempotent), blocks, policy and
/// resume, each write audited, and the entitlement read sees it.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn og25_controls_round_trip_and_are_audited() -> Result<()> {
    use db::controls::{Change, apply, get, read_with};
    let pool = test_pool().await?;
    let t = og23_tenant(&pool, "og25-controls").await?;
    assert_eq!(
        get(&pool, &t).await?,
        db::controls::ControlsRow::default(),
        "no row = nothing set"
    );
    let first = apply(
        &pool,
        &t,
        &Change::Pause {
            reason: Some("incident".into()),
        },
        "owner",
    )
    .await?;
    let at = first.paused_at.expect("paused");
    let again = apply(
        &pool,
        &t,
        &Change::Pause {
            reason: Some("other".into()),
        },
        "owner",
    )
    .await?;
    assert_eq!(
        again.paused_at,
        Some(at),
        "pausing again keeps the first pause"
    );
    assert_eq!(again.pause_reason.as_deref(), Some("incident"));
    apply(
        &pool,
        &t,
        &Change::Blocks {
            models: Some(vec!["gpt-4o*".into()]),
            providers: None,
            end_users: Some(vec!["u1".into()]),
        },
        "owner",
    )
    .await?;
    apply(
        &pool,
        &t,
        &Change::Policy(Some(serde_json::json!({"limits": {"rpm": 5}}))),
        "owner",
    )
    .await?;
    let client = pool.get().await?;
    let row = read_with(&client, t.as_uuid()).await?.expect("a row");
    assert_eq!(row.blocked_models, vec!["gpt-4o*".to_string()]);
    assert_eq!(row.blocked_end_users, vec!["u1".to_string()]);
    assert!(row.blocked_providers.is_empty());
    assert!(row.paused_at.is_some());
    assert_eq!(
        row.policy.as_ref().unwrap()["limits"]["rpm"],
        serde_json::json!(5)
    );
    let resumed = apply(&pool, &t, &Change::Resume, "owner").await?;
    assert!(resumed.paused_at.is_none());
    let n: i64 = client
        .query_one(
            "SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id = $1 \
             AND action LIKE 'workspace.%'",
            &[t.as_uuid()],
        )
        .await?
        .get(0);
    assert_eq!(n, 5);
    Ok(())
}

/// OG-24 proof 5: the outbox admits ONE row per (channel, dedup key) — a second crossing
/// of the same threshold in the same window inserts nothing; the next window fires again;
/// another tenant's channels never receive it; claimed rows are leased.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn og24_the_outbox_fires_a_threshold_once_per_channel_per_window() -> Result<()> {
    use db::spend_alerts::*;
    let pool = test_pool().await?;
    let t = og23_tenant(&pool, "og24-a").await?;
    let other = og23_tenant(&pool, "og24-b").await?;
    for (tenant, n) in [(&t, 2usize), (&other, 1)] {
        for i in 0..n {
            let out = create_channel(
                &pool,
                tenant,
                &NewChannel {
                    id: Uuid::new_v4(),
                    kind: "email",
                    name: format!("ch{i}"),
                    target: format!("ops{i}@example.com"),
                    secret_enc: None,
                },
                20,
                "owner",
            )
            .await?;
            assert!(matches!(out, CreateOutcome::Created(_)));
        }
    }
    let payload = serde_json::json!({"threshold": "80%"});
    let key = "budget:workspace:workspace:monthly:80%:202610";
    assert_eq!(
        enqueue(&pool, *t.as_uuid(), key, &payload).await?,
        2,
        "one row per channel"
    );
    assert_eq!(
        enqueue(&pool, *t.as_uuid(), key, &payload).await?,
        0,
        "never twice"
    );
    assert_eq!(
        enqueue(
            &pool,
            *t.as_uuid(),
            "budget:workspace:workspace:monthly:80%:202611",
            &payload
        )
        .await?,
        2,
        "the next window fires again"
    );
    let due = claim_due(&pool, 50, 300).await?;
    assert_eq!(due.len(), 4);
    assert!(due.iter().all(|d| d.channel.tenant_id == *t.as_uuid()));
    assert!(
        claim_due(&pool, 50, 300).await?.is_empty(),
        "claimed rows are leased"
    );
    record_outcome(&pool, due[0].event_id, Ok(()), 30, false).await?;
    let ev = list_events(&pool, &t, 10).await?;
    assert_eq!(ev.iter().filter(|e| e["status"] == "delivered").count(), 1);
    Ok(())
}

/// OG-51: the cache settings, the invalidation epochs and a key's narrowing round-trip through
/// REAL rows; each write is audited with before and after; a second identical write records
/// nothing; the epoch row cap holds; a garbage stored key document reads as OFF (fail-closed);
/// and another tenant sees none of it.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn og51_cache_settings_epochs_and_key_narrowing_round_trip_and_are_audited() -> Result<()> {
    use db::api_keys::{KeyEditor, KeyPatch, MintOptions, UpdateOutcome, mint, update};
    use db::cache_settings::*;
    let pool = test_pool().await?;
    let t = og23_tenant(&pool, "og51-a").await?;
    let other = og23_tenant(&pool, "og51-b").await?;
    let client = pool.get().await?;
    assert_eq!(
        read_with(&client, t.as_uuid()).await?,
        Loaded::default(),
        "no rows = nothing set = today's behaviour"
    );

    // Settings: written, read back, audited with before AND after.
    let want = Settings {
        mode: Mode::On,
        ttl_hours: Some(24),
        namespace_by: NamespaceBy::Key,
        semantic: false,
    };
    let first = set_settings(&pool, &t, &want, "owner").await?;
    assert!(first.changed);
    assert_eq!(first.previous, Settings::default());
    let loaded = read_with(&client, t.as_uuid()).await?;
    assert_eq!(loaded.settings, want);
    assert!(loaded.updated_at.is_some());
    let again = set_settings(&pool, &t, &want, "owner").await?;
    assert!(!again.changed, "the same document again changes nothing");
    let audit = client
        .query(
            "SELECT before_json, after_json FROM admin_audit_log \
             WHERE actor_workspace_id = $1 AND action = 'cache.settings.set'",
            &[t.as_uuid()],
        )
        .await?;
    assert_eq!(audit.len(), 1, "one control-change row, none for the no-op");
    let (before, after): (serde_json::Value, serde_json::Value) =
        (audit[0].get(0), audit[0].get(1));
    assert_eq!(before["mode"], "inherit");
    assert_eq!(after["mode"], "on");
    assert_eq!(after["ttl_hours"], 24);
    assert_eq!(after["namespace_by"], "key");

    // The CHECK constraints are the last line: a value the route would never send is refused.
    assert!(
        client
            .execute(
                "UPDATE workspace_cache_settings SET namespace_by = 'galaxy' WHERE tenant_id = $1",
                &[t.as_uuid()]
            )
            .await
            .is_err()
    );

    // Epochs: a counter that only goes up, audited, capped per workspace.
    let key_scope = format!("key:{}", Uuid::new_v4());
    assert_eq!(
        bump_epoch(&pool, &t, "workspace", 2, "owner").await?,
        BumpOutcome::Bumped { epoch: 1 }
    );
    assert_eq!(
        bump_epoch(&pool, &t, "workspace", 2, "owner").await?,
        BumpOutcome::Bumped { epoch: 2 }
    );
    assert_eq!(
        bump_epoch(&pool, &t, &key_scope, 2, "owner").await?,
        BumpOutcome::Bumped { epoch: 1 }
    );
    assert_eq!(
        bump_epoch(&pool, &t, "model:gpt-4o", 2, "owner").await?,
        BumpOutcome::LimitReached { max: 2 },
        "the 3rd NEW scope is refused at the cap"
    );
    assert_eq!(
        bump_epoch(&pool, &t, "workspace", 2, "owner").await?,
        BumpOutcome::Bumped { epoch: 3 },
        "an existing scope is still bumpable at the cap"
    );
    let loaded = read_with(&client, t.as_uuid()).await?;
    assert_eq!(loaded.epoch("workspace"), 3);
    assert_eq!(loaded.epoch(&key_scope), 1);
    assert_eq!(
        loaded.epoch("model:gpt-4o"),
        0,
        "the refused scope has no row"
    );
    let n: i64 = client
        .query_one(
            "SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id = $1 \
             AND action = 'cache.invalidate'",
            &[t.as_uuid()],
        )
        .await?
        .get(0);
    assert_eq!(n, 4, "one row per bump; the refused one wrote nothing");
    // Another tenant's cache is untouched.
    assert_eq!(
        read_with(&client, other.as_uuid()).await?,
        Loaded::default()
    );

    // A key's narrowing rides PATCH, is audited as a key update, and is read per tenant.
    let key = mint(&pool, &t, "narrowed", None, MintOptions::default()).await?;
    let patch = KeyPatch {
        cache: Some(Some(serde_json::json!({"mode": "off"}))),
        ..Default::default()
    };
    let UpdateOutcome::Updated { record, changed } =
        update(&pool, &t, key.api_key.id, KeyEditor::Any, &patch, "owner").await?
    else {
        panic!("expected Updated");
    };
    assert_eq!(changed, vec!["cache"]);
    assert_eq!(record.cache, Some(serde_json::json!({"mode": "off"})));
    let loaded = read_with(&client, t.as_uuid()).await?;
    assert!(loaded.keys[&key.api_key.id].off);
    assert!(read_with(&client, other.as_uuid()).await?.keys.is_empty());
    // Stored garbage is read as OFF — the narrowing direction, never ignored.
    client
        .execute(
            "UPDATE api_keys SET cache = '{\"mode\":\"on\"}'::jsonb WHERE id = $1",
            &[&key.api_key.id],
        )
        .await?;
    assert!(
        read_with(&client, t.as_uuid()).await?.keys[&key.api_key.id].off,
        "a key document that tries to turn the cache ON is read as off"
    );
    // Clearing removes the narrowing (the owner decision that widens).
    let clear = KeyPatch {
        cache: Some(None),
        ..Default::default()
    };
    let UpdateOutcome::Updated { changed, .. } =
        update(&pool, &t, key.api_key.id, KeyEditor::Any, &clear, "owner").await?
    else {
        panic!("expected Updated");
    };
    assert_eq!(changed, vec!["cache"]);
    assert!(read_with(&client, t.as_uuid()).await?.keys.is_empty());
    Ok(())
}

/// OG-50: an export round-trips through real rows; the sealed blob never reaches a list or an
/// audit row; the plan cap holds; tenant isolation holds on every statement; the status flush
/// only moves `last_success_at` forward; the directory returns enabled exports only.
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn og50_exports_round_trip_are_sealed_isolated_and_audited() -> Result<()> {
    use db::otel_exports::*;
    let pool = test_pool().await?;
    let t = og23_tenant(&pool, "og50-a").await?;
    let other = og23_tenant(&pool, "og50-b").await?;
    let client = pool.get().await?;
    let new = |name: &str, sealed: Option<&str>| NewExport {
        id: Uuid::new_v4(),
        name: name.into(),
        url: "https://collector.example.com/v1/traces?token=URLSECRET".into(),
        headers_enc: sealed.map(str::to_owned),
        header_names: if sealed.is_some() {
            vec!["authorization".into()]
        } else {
            Vec::new()
        },
        include_content: false,
        sample_ratio: 0.5,
        only_errors: false,
    };
    let a = new("prod", Some("SEALED-BLOB-AAA"));
    let CreateOutcome::Created(created) = create(&pool, &t, &a, 1, "owner").await? else {
        panic!("expected Created")
    };
    assert_eq!(created.status, "never_delivered");
    assert_eq!(created.header_names, vec!["authorization".to_string()]);
    assert!(
        matches!(
            create(&pool, &t, &new("second", None), 1, "owner").await?,
            CreateOutcome::LimitReached { max: 1 }
        ),
        "the plan cap holds"
    );
    // The blob is in the row, in the one column, and nowhere a reader looks.
    let stored: Option<String> = client
        .query_one(
            "SELECT headers_enc FROM otel_exports WHERE id = $1",
            &[&a.id],
        )
        .await?
        .get(0);
    assert_eq!(stored.as_deref(), Some("SEALED-BLOB-AAA"));
    let listed = list(&pool, &t).await?;
    assert_eq!(listed.len(), 1);
    assert!(!format!("{listed:?}").contains("SEALED-BLOB"));
    assert!(
        list(&pool, &other).await?.is_empty(),
        "another tenant lists none"
    );

    // Update: audited with before AND after; the audit row never holds the blob or the URL query.
    let patch = Patch {
        enabled: Some(false),
        headers: Some((None, Vec::new())),
        ..Default::default()
    };
    assert!(
        update(&pool, &other, a.id, &patch, "owner")
            .await?
            .is_none(),
        "another tenant cannot update it"
    );
    let updated = update(&pool, &t, a.id, &patch, "owner")
        .await?
        .expect("updated");
    assert!(!updated.enabled);
    assert!(updated.header_names.is_empty());
    let audit = client
        .query(
            "SELECT before_json::text, after_json::text FROM admin_audit_log \
             WHERE actor_workspace_id = $1 AND action IN ('otel_export.create', 'otel_export.update')",
            &[t.as_uuid()],
        )
        .await?;
    assert_eq!(audit.len(), 2, "create + update, one row each");
    for r in &audit {
        let text = format!(
            "{} {}",
            r.get::<_, Option<String>>(0).unwrap_or_default(),
            r.get::<_, Option<String>>(1).unwrap_or_default()
        );
        assert!(
            !text.contains("SEALED-BLOB") && !text.contains("URLSECRET"),
            "{text}"
        );
        assert!(
            text.contains("collector.example.com"),
            "the host is recorded"
        );
    }
    let stored: Option<String> = client
        .query_one(
            "SELECT headers_enc FROM otel_exports WHERE id = $1",
            &[&a.id],
        )
        .await?
        .get(0);
    assert_eq!(stored, None, "headers: null cleared the sealed map");

    // The directory returns ENABLED exports only; the tenant-scoped sealed read is isolated.
    assert!(directory(&pool).await?.iter().all(|s| s.id != a.id));
    update(
        &pool,
        &t,
        a.id,
        &Patch {
            enabled: Some(true),
            ..Default::default()
        },
        "owner",
    )
    .await?;
    assert!(directory(&pool).await?.iter().any(|s| s.id == a.id));
    assert!(get_sealed(&pool, &other, a.id).await?.is_none());
    assert!(get_sealed(&pool, &t, a.id).await?.is_some());

    // The status flush: counters set, last_success_at only forward.
    let now = chrono::Utc::now();
    let flush = |ok_at: Option<chrono::DateTime<chrono::Utc>>, delivered: i64| StatusUpdate {
        id: a.id,
        tenant_id: *t.as_uuid(),
        status: "ok",
        last_success_at: ok_at,
        last_error_class: None,
        delivered,
        dropped: 2,
        failed: 3,
    };
    flush_status(&pool, &[flush(Some(now), 10)]).await?;
    flush_status(&pool, &[flush(Some(now - chrono::Duration::hours(1)), 11)]).await?;
    flush_status(&pool, &[flush(None, 12)]).await?;
    let row = list(&pool, &t).await?.remove(0);
    assert_eq!((row.delivered, row.dropped, row.failed), (12, 2, 3));
    assert_eq!(row.status, "ok");
    let at = row.last_success_at.expect("set");
    assert!(
        (at - now).num_seconds().abs() <= 1,
        "an older success never moves it back"
    );

    // Delete: audited; another tenant cannot.
    assert!(!delete(&pool, &other, a.id, "owner").await?);
    assert!(delete(&pool, &t, a.id, "owner").await?);
    assert!(!delete(&pool, &t, a.id, "owner").await?, "already gone");
    let n: i64 = client
        .query_one(
            "SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id = $1 \
             AND action = 'otel_export.delete'",
            &[t.as_uuid()],
        )
        .await?
        .get(0);
    assert_eq!(n, 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires isolated migrated Postgres; never run against production"]
async fn og32_rotation_rewraps_both_adapter_bound_credentials() -> Result<()> {
    use base64::Engine as _;
    use secrecy::{ExposeSecret as _, SecretString};
    let pool = test_pool().await?;
    let tenant = Uuid::new_v4();
    db::tenants::create(&pool, tenant, "adapter-rotation", "free").await?;
    let k0 = base64::engine::general_purpose::STANDARD.encode([0x44_u8; 32]);
    let k1 = base64::engine::general_purpose::STANDARD.encode([0x55_u8; 32]);
    let old = byok::ByokMasterKey::from_values(Some(&k0), None, None)?.unwrap();
    let current =
        byok::ByokMasterKey::from_values(Some(&k0), Some(&format!("1:{k1}")), Some(1))?.unwrap();
    let secret = SecretString::from("synthetic-vendor-key");
    let mut rows = Vec::new();
    for (kind, endpoint) in [
        ("lakera", "https://api.lakera.ai/v2/guard"),
        (
            "azure_content_safety",
            "https://unit.cognitiveservices.azure.com",
        ),
    ] {
        let id = Uuid::new_v4();
        let aad = byok::guardrail_hook_aad(&tenant, &format!("{kind}:{id}:{endpoint}"));
        let sealed = old.encrypt_with_context(&secret, &aad)?;
        let mut adapter = serde_json::json!({"kind":kind});
        if kind == "azure_content_safety" {
            adapter["thresholds"] =
                serde_json::json!({"Hate":4,"SelfHarm":4,"Sexual":4,"Violence":4});
        }
        let config = serde_json::json!({"endpoint":endpoint,"adapter":adapter,"pre":true,"post":false,"timeout_ms":1000});
        pool.get().await?.execute("INSERT INTO guardrail_hooks (tenant_id,id,config,ciphertext_b64,updated_by) VALUES ($1,$2,$3,$4,'test')",&[&tenant,&id,&config,&sealed]).await?;
        rows.push((id, aad));
    }
    let report = byok_rotate::rotate(&pool, &current, false).await?;
    assert_eq!(report.remaining(), 0);
    assert_eq!(report.tables.iter().map(|t| t.rewrapped).sum::<u64>(), 2);
    for (id, aad) in rows {
        let value: String = pool
            .get()
            .await?
            .query_one(
                "SELECT ciphertext_b64 FROM guardrail_hooks WHERE tenant_id = $1 AND id = $2",
                &[&tenant, &id],
            )
            .await?
            .get(0);
        assert_eq!(byok::ByokMasterKey::kek_id_of(&value), Some(1));
        assert_eq!(
            current.decrypt_with_context(&value, &aad)?.expose_secret(),
            secret.expose_secret()
        );
    }
    Ok(())
}

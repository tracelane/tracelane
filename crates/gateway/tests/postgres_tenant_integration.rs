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
    upsert(&pool, &a, "anthropic", "unit-test-ciphertext-only", "test").await?;
    let source = get(&pool, &a, "anthropic").await?.unwrap();
    assert!(source.saved_at <= chrono::Utc::now());
    assert!(source.last_validation.is_none());
    assert!(get(&pool, &b, "anthropic").await?.is_none());
    let result = KeyValidation {
        status: "valid".into(),
        reason: "authenticated".into(),
        checked_at: chrono::Utc::now(),
    };
    assert!(!record_validation(&pool, &b, &source, "other-owner", &result).await?);
    assert!(record_validation(&pool, &a, &source, "owner-a", &result).await?);
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
        "unit-test-replacement-ciphertext",
        "next",
    )
    .await?;
    assert!(list(&pool, &a).await?[0].last_validation.is_none());
    assert!(!record_validation(&pool, &a, &source, "owner-a", &result).await?);
    let client = pool.get().await?;
    let audit = client.query_one("SELECT actor_user_id, after_json::text FROM admin_audit_log WHERE actor_workspace_id = $1 AND action = 'provider_key.validate'", &[a.as_uuid()]).await?;
    assert_eq!(audit.get::<_, &str>(0), "owner-a");
    assert!(!audit.get::<_, &str>(1).contains("ciphertext"));
    delete(&pool, &a, "anthropic").await?;
    assert!(!record_validation(&pool, &a, &source, "owner-a", &result).await?);
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
    let audits: i64 = client
        .query_one(
            "SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id = $1",
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
    let audits = || async move {
        let n: i64 = c
            .query_one(
                "SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id = $1",
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
    db::provider_keys::upsert(&pool, &tenant, "openai", &v2, "tuse").await?;
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

    // The rotated process: both keys, KEK 1 active.
    let ring = byok::ByokMasterKey::from_values(Some(&k0), Some(&format!("1:{k1}")), Some(1))?
        .expect("ring");
    assert_eq!(ring.active_kek(), 1);

    // Dry run: reports, writes nothing.
    let dry = byok_rotate::rotate(&pool, &ring, true).await?;
    assert_eq!(
        dry.tables.iter().map(|t| t.rewrapped).sum::<u64>(),
        3,
        "{}",
        dry.render()
    );
    assert_eq!(dry.remaining(), 3);
    let still_v2 = db::provider_keys::get(&pool, &tenant, "openai")
        .await?
        .expect("row");
    assert_eq!(still_v2.ciphertext_b64, v2, "dry-run must not write");

    // Execute.
    let run = byok_rotate::rotate(&pool, &ring, false).await?;
    assert_eq!(run.failed(), 0, "{}", run.render());
    assert_eq!(run.remaining(), 0, "{}", run.render());
    assert_eq!(
        run.tables.iter().map(|t| t.rewrapped).sum::<u64>(),
        3,
        "{}",
        run.render()
    );

    // The row is now v3 under KEK 1, decrypts under the ring, and NOT under KEK 0 alone.
    let moved = db::provider_keys::get(&pool, &tenant, "openai")
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
    // Idempotent: a second run has nothing to do.
    let again = byok_rotate::rotate(&pool, &ring, false).await?;
    assert_eq!(
        again.tables.iter().map(|t| t.rewrapped).sum::<u64>(),
        0,
        "{}",
        again.render()
    );
    assert_eq!(again.tables.iter().map(|t| t.current).sum::<u64>(), 3);

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
    db::provider_keys::upsert(&pool, &tenant, "cohere", &foreign, "tuse").await?;
    let with_foreign = byok_rotate::rotate(&pool, &ring, false).await?;
    assert_eq!(with_foreign.failed(), 1, "{}", with_foreign.render());
    assert_eq!(with_foreign.tables[0].unreadable, 1);
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

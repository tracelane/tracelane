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

fn url() -> Option<String> {
    std::env::var("POSTGRES_TEST_URL").ok()
}

fn require_url() -> String {
    url().expect(
        "POSTGRES_TEST_URL not set — run with `POSTGRES_TEST_URL=postgres://… \
         cargo test --features prompt-promotion-preview --test \
         postgres_tenant_integration -- --ignored`",
    )
}

async fn test_pool() -> Result<deadpool_postgres::Pool> {
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
    cfg.dbname = pg_cfg.get_dbname().map(str::to_owned);
    let pool = cfg.create_pool(
        Some(deadpool_postgres::Runtime::Tokio1),
        tokio_postgres::NoTls,
    )?;
    db::apply_migrations(&pool).await?;
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
    )
    .await?;

    // Hot-path lookup must round-trip
    let resolved = db::api_keys::lookup_tenant_by_key_body(&pool, &key_body).await?;
    let (resolved, _key_id) = resolved.expect("api key should resolve");
    assert_eq!(resolved.as_uuid().to_string(), tenant_id.to_string());

    // Unknown key body must NOT resolve
    let unknown = db::api_keys::lookup_tenant_by_key_body(&pool, "nope_does_not_exist").await?;
    assert!(unknown.is_none(), "unknown key body must return None");

    // Revoked keys must NOT resolve
    db::api_keys::revoke(&pool, created.id).await?;
    let after_revoke = db::api_keys::lookup_tenant_by_key_body(&pool, &key_body).await?;
    assert!(
        after_revoke.is_none(),
        "revoked api key must no longer resolve"
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

    db::tenants::set_plan_tier(&pool, &tenant_wrapped, "team").await?;
    let after_upgrade = db::tenants::get(&pool, &tenant_wrapped).await?;
    assert_eq!(after_upgrade.unwrap().plan_tier, "team");

    Ok(())
}

/// Smoke test runs without Postgres — proves the authoritative Drizzle
/// migration SQL embeds correctly + the peppered_lookup derivation honours its
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

    let _ = db::api_keys::init_pepper(&"22".repeat(32));
    let h1 = db::api_keys::peppered_lookup("abc123").unwrap();
    let h2 = db::api_keys::peppered_lookup("abc123").unwrap();
    assert_eq!(h1, h2);
    assert_eq!(h1.len(), 32);
}

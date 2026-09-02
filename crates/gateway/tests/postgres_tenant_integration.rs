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
async fn create_fresh_database() -> Result<String> {
    let admin_url = require_url();
    let (client, conn) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls).await?;
    let handle = tokio::spawn(conn);
    let db = format!("tlane_it_{}", Uuid::new_v4().simple());
    let created = client.batch_execute(&format!("CREATE DATABASE {db}")).await;
    drop(client);
    let _ = handle.await;
    created.map_err(|e| anyhow::anyhow!("CREATE DATABASE {db} failed (needs createdb): {e}"))?;
    Ok(db)
}

async fn test_pool() -> Result<deadpool_postgres::Pool> {
    // Re-implement build_pool inline — db::build_pool reads POSTGRES_URL,
    // which we deliberately don't set in CI test runs.
    let url = require_url();
    let fresh_db = create_fresh_database().await?;
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
    cfg.dbname = Some(fresh_db);
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

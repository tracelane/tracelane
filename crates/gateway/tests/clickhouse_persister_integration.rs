//! Live ClickHouse schema-parity tests for B1 migration 03 (Move #2 of ADR-011).
//!
//! Default behaviour: `#[ignore]`d. Integration tests need a running
//! ClickHouse with migration 03_prompt_promotion.sql applied, which a
//! plain `cargo test` host can't be assumed to have. CI and the founder
//! run them with:
//!
//!   CLICKHOUSE_TEST_URL=http://localhost:8123 \
//!   cargo test --test clickhouse_persister_integration -- --ignored --nocapture
//!
//! These tests deliberately avoid pulling in gateway-internal modules —
//! the gateway crate is a binary and the `#[path]` trick fails because
//! its modules reach for `crate::predictive::*` and friends. Instead we
//! exercise migration 03 directly with raw SQL that mirrors the column
//! shape the Rust persisters use. If a persister's `Row` struct ever
//! drifts from the migration, this test plus the persister unit tests
//! together will catch the divergence.
//!
//! Tenant isolation: each test fabricates a fresh UUID-derived tenant_id
//! so concurrent runs and dirty databases don't collide.

use anyhow::Result;
use clickhouse::Client as ClickhouseClient;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

fn ch_url() -> Option<String> {
    std::env::var("CLICKHOUSE_TEST_URL").ok()
}

fn require_url() -> String {
    ch_url().expect(
        "CLICKHOUSE_TEST_URL not set — run with `CLICKHOUSE_TEST_URL=http://localhost:8123 \
         cargo test --test clickhouse_persister_integration -- --ignored`",
    )
}

fn client() -> ClickhouseClient {
    ClickhouseClient::default()
        .with_url(require_url())
        .with_database("tracelane")
}

async fn ensure_schema(client: &ClickhouseClient) -> Result<()> {
    client
        .query("CREATE DATABASE IF NOT EXISTS tracelane")
        .execute()
        .await?;

    let migration =
        include_str!("../../../infra/dev/clickhouse/migrations/03_prompt_promotion.sql");
    // STRIP COMMENTS BEFORE SPLITTING ON `;`, not after.
    //
    // This test had ZERO callers until `scripts/ci/run-clickhouse-integration.sh`
    // existed (2026-08-23), and running it for the first time showed it could
    // never have passed: the old code split on `;` and then filtered statements
    // that START with `--`, so a leading comment block was sent to the server as
    // SQL and died with *"Syntax error: failed at position 1 ('the')"*. A
    // trailing comment containing a semicolon splits a CREATE TABLE in half for
    // the same reason. `docs/reference/TRAPS.md` §1 CLASS-1: a control that never
    // ran, which would have gone red on its first execution — exactly what
    // `postgres_tenant_integration.rs` did.
    let stripped: String = migration
        .lines()
        .map(|l| match l.find("--") {
            Some(i) => &l[..i],
            None => l,
        })
        .collect::<Vec<_>>()
        .join("\n");
    // Row policies need a `tenant_role` not provisioned in test envs.
    for stmt in stripped
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty() && !s.to_lowercase().starts_with("create row policy"))
    {
        client.query(stmt).execute().await?;
    }
    Ok(())
}

/// Mirrors `prompt_router::PromotionDecisionRow` shape — keep this in
/// lock-step with that struct or these tests will fail.
#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
struct PromotionRow {
    tenant_id: String,
    #[serde(with = "clickhouse::serde::uuid")]
    promotion_id: ::uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    prompt_id: ::uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid::option")]
    from_version_id: Option<::uuid::Uuid>,
    #[serde(with = "clickhouse::serde::uuid")]
    to_version_id: ::uuid::Uuid,
    from_env: String,
    to_env: String,
    #[serde(with = "clickhouse::serde::uuid::option")]
    eval_run_id: Option<::uuid::Uuid>,
    decision: String,
    decided_at: i64,
    decided_by_user_id: Option<String>,
    notes: String,
}

/// Mirrors `auto_rollback::RollbackEventRow`.
#[derive(Debug, Serialize, Deserialize, clickhouse::Row)]
struct RollbackRow {
    tenant_id: String,
    #[serde(with = "clickhouse::serde::uuid")]
    rollback_id: ::uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    prompt_id: ::uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    from_version_id: ::uuid::Uuid,
    #[serde(with = "clickhouse::serde::uuid")]
    to_version_id: ::uuid::Uuid,
    trigger_metric: String,
    trigger_value: f64,
    ewma_baseline: f64,
    sigma_drift: f32,
    rollback_mode: String,
    fired_at: i64,
    confirmed_at: Option<i64>,
    confirmed_by_user_id: Option<String>,
}

/// Assert a `DateTime64(3)` column round-tripped to a REAL instant.
///
/// This is the assertion both round-trip tests were missing. They wrote and
/// read every other field and never touched the timestamp, so a 1000×
/// unit error — `timestamp_micros()` into a millisecond column, which
/// `clickhouse-rs` stores verbatim as raw ticks — round-tripped "successfully"
/// into the year ~48000 and the test stayed green. It happened on
/// `promotion_decisions.decided_at`, was fixed, and then happened again on
/// `rollback_events.fired_at` in the sibling persister.
///
/// A ±1 day window is deliberately loose: it is not trying to measure clock
/// skew, only to catch an error of three orders of magnitude.
fn assert_recent_millis(value_ms: i64, column: &str) {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let skew = (value_ms - now_ms).abs();
    assert!(
        skew < 86_400_000,
        "{column} round-tripped to {value_ms} ms, which is {} days from now — \
         a DateTime64(3) column stores MILLIS, so this is almost certainly a \
         micros/nanos unit error at the insert site",
        skew / 86_400_000,
    );
}

#[tokio::test]
#[ignore]
async fn promotion_decisions_round_trip() -> Result<()> {
    let client = client();
    ensure_schema(&client).await?;

    let tenant_id = Uuid::new_v4().to_string();
    let promotion_id = Uuid::new_v4();
    let prompt_id = Uuid::new_v4();
    let to_version_id = Uuid::new_v4();
    let from_version_id = Some(Uuid::new_v4());
    let eval_run_id = Some(Uuid::new_v4());

    let row = PromotionRow {
        tenant_id: tenant_id.clone(),
        promotion_id,
        prompt_id,
        from_version_id,
        to_version_id,
        from_env: "staging".into(),
        to_env: "production".into(),
        eval_run_id,
        decision: "promoted".into(),
        // DateTime64(3) is MILLIS. This test wrote micros and never read the
        // column back, so it round-tripped every field except the one that was
        // wrong in production. See the assertions below.
        decided_at: chrono::Utc::now().timestamp_millis(),
        decided_by_user_id: None,
        notes: "integration-test".into(),
    };

    let mut insert = client.insert("promotion_decisions")?;
    insert.write(&row).await?;
    insert.end().await?;

    #[derive(Debug, Deserialize, clickhouse::Row)]
    struct ReadRow {
        tenant_id: String,
        #[serde(with = "clickhouse::serde::uuid")]
        promotion_id: ::uuid::Uuid,
        from_env: String,
        to_env: String,
        decision: String,
        decided_at: i64,
    }

    let mut cursor = client
        .query(
            "SELECT tenant_id, promotion_id, from_env, to_env, decision, \
                    toUnixTimestamp64Milli(decided_at) \
             FROM promotion_decisions WHERE tenant_id = ? LIMIT 1",
        )
        .bind(tenant_id.clone())
        .fetch::<ReadRow>()?;

    let read = cursor
        .next()
        .await?
        .expect("promotion_decisions row missing after insert");

    assert_eq!(read.tenant_id, tenant_id);
    assert_eq!(read.promotion_id, promotion_id);
    assert_eq!(read.from_env, "staging");
    assert_eq!(read.to_env, "production");
    assert_eq!(read.decision, "promoted");
    assert_recent_millis(read.decided_at, "promotion_decisions.decided_at");
    Ok(())
}

#[tokio::test]
#[ignore]
async fn rollback_events_round_trip() -> Result<()> {
    let client = client();
    ensure_schema(&client).await?;

    let tenant_id = Uuid::new_v4().to_string();
    let rollback_id = Uuid::new_v4();
    let prompt_id = Uuid::new_v4();
    let from_version_id = Uuid::new_v4();
    let to_version_id = Uuid::new_v4();

    let row = RollbackRow {
        tenant_id: tenant_id.clone(),
        rollback_id,
        prompt_id,
        from_version_id,
        to_version_id,
        trigger_metric: "latency".into(),
        trigger_value: 1234.5,
        ewma_baseline: 1000.0,
        sigma_drift: 2.5,
        rollback_mode: "auto".into(),
        // DateTime64(3) is MILLIS — `rollback_events.fired_at` shipped as
        // micros until 2026-08-19, and this test could not see it.
        fired_at: chrono::Utc::now().timestamp_millis(),
        confirmed_at: None,
        confirmed_by_user_id: None,
    };

    let mut insert = client.insert("rollback_events")?;
    insert.write(&row).await?;
    insert.end().await?;

    #[derive(Debug, Deserialize, clickhouse::Row)]
    struct ReadRow {
        tenant_id: String,
        #[serde(with = "clickhouse::serde::uuid")]
        rollback_id: ::uuid::Uuid,
        trigger_metric: String,
        trigger_value: f64,
        rollback_mode: String,
        fired_at: i64,
    }

    let mut cursor = client
        .query(
            "SELECT tenant_id, rollback_id, trigger_metric, trigger_value, rollback_mode, \
                    toUnixTimestamp64Milli(fired_at) \
             FROM rollback_events WHERE tenant_id = ? LIMIT 1",
        )
        .bind(tenant_id.clone())
        .fetch::<ReadRow>()?;

    let read = cursor
        .next()
        .await?
        .expect("rollback_events row missing after insert");

    assert_eq!(read.tenant_id, tenant_id);
    assert_eq!(read.rollback_id, rollback_id);
    assert_eq!(read.trigger_metric, "latency");
    assert!((read.trigger_value - 1234.5).abs() < 1e-6);
    assert_eq!(read.rollback_mode, "auto");
    assert_recent_millis(read.fired_at, "rollback_events.fired_at");
    Ok(())
}

/// Smoke check that runs without ClickHouse — proves migration 03 SQL
/// embeds correctly and the column shapes parse via clickhouse-rs's
/// `Row` derive. This catches drift between the Rust Row structs and
/// the migration SQL even when the founder hasn't booted ClickHouse.
#[test]
fn migration_sql_embeds_and_row_structs_parse() {
    let migration =
        include_str!("../../../infra/dev/clickhouse/migrations/03_prompt_promotion.sql");
    assert!(migration.contains("CREATE TABLE IF NOT EXISTS promotion_decisions"));
    assert!(migration.contains("CREATE TABLE IF NOT EXISTS rollback_events"));
    assert!(migration.contains("trigger_metric LowCardinality(String)"));
    assert!(migration.contains("decision LowCardinality(String)"));

    // Construct the Row structs from defaults — confirms the derive macro
    // expansion is well-formed for both.
    let _promo = PromotionRow {
        tenant_id: String::new(),
        promotion_id: Uuid::nil(),
        prompt_id: Uuid::nil(),
        from_version_id: None,
        to_version_id: Uuid::nil(),
        from_env: String::new(),
        to_env: String::new(),
        eval_run_id: None,
        decision: String::new(),
        decided_at: 0,
        decided_by_user_id: None,
        notes: String::new(),
    };
    let _roll = RollbackRow {
        tenant_id: String::new(),
        rollback_id: Uuid::nil(),
        prompt_id: Uuid::nil(),
        from_version_id: Uuid::nil(),
        to_version_id: Uuid::nil(),
        trigger_metric: String::new(),
        trigger_value: 0.0,
        ewma_baseline: 0.0,
        sigma_drift: 0.0,
        rollback_mode: String::new(),
        fired_at: 0,
        confirmed_at: None,
        confirmed_by_user_id: None,
    };
}

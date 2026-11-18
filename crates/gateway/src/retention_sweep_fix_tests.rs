//! Real-store deletion regressions; run serially on the disposable FIX services.
use super::*;
const LIVE: &str = "00000000-0000-0000-0000-00000000fa11";

#[cfg(test)]
async fn fixture() -> (DbPool, clickhouse::Client, String) {
    let url = retention_test_fixture::disposable_url();
    let ch = retention_test_fixture::reset(&url).await;
    let pool = tests::tombstone_pg_fixture().await;
    // Minimal real schemas for every table the production sweep visits.
    for name in SWEEP_TABLES
        .iter()
        .map(|t| t.label)
        .chain(ORPHAN_ONLY_TABLES.iter().map(|t| t.label))
    {
        ch.query(&format!("CREATE TABLE tracelane.{name} (tenant_id String, start_time DateTime, recorded_at DateTime, event_time DateTime, scored_at DateTime, captured_at DateTime, created_at DateTime, day Date) ENGINE=MergeTree ORDER BY tenant_id")).execute().await.unwrap();
    }
    ch.query("INSERT INTO tracelane.spans (tenant_id,start_time) VALUES (?,now()-toIntervalDay(100)),(?,now()),('sibling',now()-toIntervalDay(100))").bind(LIVE).bind(LIVE).execute().await.unwrap();
    ch.query("INSERT INTO tracelane.dataset_items (tenant_id) VALUES (?),('sibling')")
        .bind(LIVE)
        .execute()
        .await
        .unwrap();
    (pool, ch, url)
}
#[cfg(test)]
async fn count(ch: &clickhouse::Client, table: &str, tenant: &str) -> u64 {
    ch.query(&format!(
        "SELECT count() FROM tracelane.{table} WHERE tenant_id = ?"
    ))
    .bind(tenant)
    .fetch_one::<u64>()
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "disposable Postgres and ClickHouse; run serially"]
async fn og38_unresolved_live_tenant_is_never_purged() {
    let (pool, ch, url) = fixture().await;
    pool.get()
        .await
        .unwrap()
        .batch_execute("DELETE FROM plan_allowances; DELETE FROM plan_entitlements")
        .await
        .unwrap();
    let mut run = SweepRun::new(RetentionSweepPolicy::embedded());
    run_sweep_inner(&pool, &url, SweepMode::Enforce, &mut run)
        .await
        .unwrap();
    assert_eq!(
        count(&ch, "spans", LIVE).await,
        2,
        "unresolved live tenant history must survive"
    );
    assert_eq!(
        count(&ch, "dataset_items", LIVE).await,
        1,
        "curated rows are never orphans while tenant exists"
    );
    assert_eq!(count(&ch, "spans", "sibling").await, 1);
    assert_eq!(run.mutations, 0);
    assert_eq!(
        tombstone_conflicts(
            &resolve_purged(&pool).await.unwrap(),
            &resolve_retentions(&pool).await.unwrap(),
            0.0
        ),
        vec![LIVE.to_owned()]
    );
}

async fn window_changed_during_pass(sql: &str) {
    let (pool, ch, url) = fixture().await;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let mut run = SweepRun::new(RetentionSweepPolicy::embedded());
    run.before_tenant = Some(barrier.clone());
    let sweep = run_sweep_inner(&pool, &url, SweepMode::Enforce, &mut run);
    let update = async {
        barrier.wait().await; // initial window has been read; no deletion started
        pool.get().await.unwrap().batch_execute(sql).await.unwrap();
        barrier.wait().await;
    };
    let (result, ()) = tokio::join!(sweep, update);
    result.unwrap();
    assert_eq!(
        count(&ch, "spans", LIVE).await,
        2,
        "snapshot must not authorize stale deletion"
    );
    assert_eq!(count(&ch, "spans", "sibling").await, 1);
    assert_eq!(run.mutations, 0);
}
#[tokio::test]
#[ignore = "disposable Postgres and ClickHouse; run serially"]
async fn og38_retention_increase_fences_pending_deletion() {
    window_changed_during_pass("UPDATE plan_allowances SET queryable_days=730").await;
}
#[tokio::test]
#[ignore = "disposable Postgres and ClickHouse; run serially"]
async fn og38_unresolved_window_at_deletion_skips_tenant() {
    window_changed_during_pass("DELETE FROM plan_allowances; DELETE FROM plan_entitlements").await;
}

#[tokio::test]
#[ignore = "disposable ClickHouse; run serially"]
async fn og38_no_cache_reads_use_unprivileged_window() {
    let (_, ch, _) = fixture().await;
    let tenant = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::parse_str(LIVE).unwrap());
    let filtered = read_client(&ch, None, &tenant).await;
    assert_eq!(
        count(&filtered, "spans", LIVE).await,
        1,
        "OSS has the free/deny history window, never unlimited access"
    );
    assert_eq!(
        count(&ch, "spans", LIVE).await,
        2,
        "read filtering cannot delete local history"
    );
}
#[tokio::test]
#[ignore = "disposable ClickHouse; run serially"]
async fn og38_retention_read_fails_closed_after_invalidated_refresh_failure() {
    let (_, ch, _) = fixture().await;
    let tenant = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::parse_str(LIVE).unwrap());
    let failing = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let resolve = failing.clone();
    let cache = crate::entitlement_cache::EntitlementCache::new(std::sync::Arc::new(move |_| {
        let failing = resolve.load(std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move {
            if failing {
                anyhow::bail!("test resolution failed after committed change");
            }
            Ok(crate::entitlement_cache::ResolvedEntitlements {
                queryable_days: 730,
                ..crate::entitlement_cache::ResolvedEntitlements::deny_all()
            })
        })
    }));
    assert_eq!(
        count(
            &read_client(&ch, Some(&cache), &tenant).await,
            "spans",
            LIVE
        )
        .await,
        2
    );
    ch.query(
        "INSERT INTO tracelane.spans (tenant_id,start_time) VALUES (?,now()+toIntervalDay(1))",
    )
    .bind(LIVE)
    .execute()
    .await
    .unwrap();
    failing.store(true, std::sync::atomic::Ordering::SeqCst);
    cache.invalidate(*tenant.as_uuid()).await;
    assert_eq!(
        count(
            &read_client(&ch, Some(&cache), &tenant).await,
            "spans",
            LIVE
        )
        .await,
        0,
        "invalidated unknown retention must fail closed, not restore old history"
    );
}

#[tokio::test]
#[ignore = "disposable Postgres and ClickHouse; run serially"]
async fn retention_increase_before_mutation_preserves_rows() {
    let (pool, ch, url) = fixture().await;
    pool.get().await.unwrap().batch_execute(
        "UPDATE plan_allowances SET queryable_days=730;
         INSERT INTO workspace_data_controls SELECT id,30 FROM tenants;
         INSERT INTO billing_policy VALUES ('data_controls','{\"retention_days_min\":7,\"audit_addon_min_days\":180}');
         CREATE TEMP TABLE approvals (id uuid, tenant_id uuid, args_preview text, created_at timestamptz);
         INSERT INTO approvals VALUES (gen_random_uuid(),'00000000-0000-0000-0000-00000000fa11','protected preview',clock_timestamp()-interval '100 days');"
    ).await.unwrap();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let mut run = SweepRun::new(RetentionSweepPolicy::embedded());
    run.before_tenant = Some(barrier.clone());
    let sweep = run_sweep_inner(&pool, &url, SweepMode::Enforce, &mut run);
    let increase = async {
        barrier.wait().await; // old window resolved, no mutation submitted
        pool.get()
            .await
            .unwrap()
            .batch_execute("BEGIN; UPDATE workspace_data_controls SET retention_days=180; COMMIT;")
            .await
            .unwrap();
        barrier.wait().await;
    };
    let (result, ()) = tokio::join!(sweep, increase);
    result.unwrap();
    assert_eq!(
        count(&ch, "spans", LIVE).await,
        2,
        "retention increase committed before submission must protect the 100-day row"
    );
    let preview: Option<String> = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT args_preview FROM approvals WHERE tenant_id=$1::text::uuid",
            &[&LIVE],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(preview.as_deref(), Some("protected preview"));
    assert_eq!(count(&ch, "spans", "sibling").await, 1);
    assert_eq!(run.failed, 0);
    assert_eq!(
        run.skipped, 0,
        "proof must not pass by skipping the deletion path"
    );
    assert_eq!(run.mutations, 0);
}

#[tokio::test]
#[ignore = "disposable Postgres and ClickHouse; run serially"]
async fn retention_sweep_does_not_block_tenant_updates() {
    let (_, ch, url) = fixture().await;
    let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
    crate::entitlement_cache::b409_fixture::seed_v3_then_v4(&pool).await;
    let tenant = crate::entitlement_cache::b409_fixture::builder_tenant(&pool, None, None).await;
    ch.query(
        "INSERT INTO tracelane.spans (tenant_id,start_time) VALUES (?,now()-toIntervalDay(1000))",
    )
    .bind(tenant.to_string())
    .execute()
    .await
    .unwrap();
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let mut run = SweepRun::new(RetentionSweepPolicy::embedded());
    run.before_mutation = Some(barrier.clone());
    let sweep = run_sweep_inner(&pool, &url, SweepMode::Enforce, &mut run);
    let update = async {
        barrier.wait().await; // authoritative window is locked; deletion has not started
        let mut client = pool.get().await.unwrap();
        let tx = client.transaction().await.unwrap();
        tx.batch_execute("SET LOCAL lock_timeout = '1s'")
            .await
            .unwrap();
        let result = tx
            .execute(
                "UPDATE tenants SET updated_at = clock_timestamp() WHERE id = $1",
                &[&tenant],
            )
            .await;
        if result.is_ok() {
            tx.commit().await.unwrap();
        }
        barrier.wait().await;
        result
    };
    let (result, update) = tokio::join!(sweep, update);
    result.unwrap();
    assert_eq!(
        update.unwrap(),
        1,
        "the sweep must not block ordinary tenant updates"
    );
}

#[tokio::test]
#[ignore = "disposable Postgres and ClickHouse; run serially"]
async fn retention_sweep_holds_window_lock_until_submission() {
    let (_, ch, url) = fixture().await;
    let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
    crate::entitlement_cache::b409_fixture::seed_v3_then_v4(&pool).await;
    let tenant = crate::entitlement_cache::b409_fixture::builder_tenant(&pool, None, None).await;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let mut run = SweepRun::new(RetentionSweepPolicy::embedded());
    ch.query(
        "INSERT INTO tracelane.spans (tenant_id,start_time) VALUES (?,now()-toIntervalDay(1000))",
    )
    .bind(tenant.to_string())
    .execute()
    .await
    .unwrap();
    run.before_submit = Some(barrier.clone());
    let sweep = run_sweep_inner(&pool, &url, SweepMode::Enforce, &mut run);
    let probe = async {
        barrier.wait().await;
        let mut client = pool.get().await.unwrap();
        let tx = client.transaction().await.unwrap();
        let key = retention_lock_key(&tx, &tenant.to_string()).await.unwrap();
        let result = tx
            .query_one("SELECT pg_try_advisory_xact_lock($1)", &[&key])
            .await;
        barrier.wait().await;
        result
    };
    let (result, lock) = tokio::join!(sweep, probe);
    result.unwrap();
    assert!(
        !lock.unwrap().get::<_, bool>(0),
        "a retention writer must not acquire the fence between the authoritative read and deletion submission"
    );
    assert_eq!(count(&ch, "spans", &tenant.to_string()).await, 0);
    assert!(run.mutations > 0);
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    let key = retention_lock_key(&tx, &tenant.to_string()).await.unwrap();
    assert!(
        tx.query_one("SELECT pg_try_advisory_xact_lock($1)", &[&key])
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
}

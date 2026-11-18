//! Real-store retention regressions. These own the disposable FIX ClickHouse
//! tables and must run serially with the other retention proofs.
use super::*;
use std::sync::Arc;

fn disposable_urls() -> String {
    let postgres = std::env::var("POSTGRES_TEST_URL").expect("disposable Postgres URL");
    let pg: tokio_postgres::Config = postgres.parse().unwrap();
    assert_eq!(pg.get_ports(), &[15438]);
    retention_test_fixture::disposable_url()
}

#[cfg(test)]
async fn empty_sweep_tables(url: &str) {
    let ch = retention_test_fixture::reset(url).await;
    // These are empty; their only purpose is letting the complete sweep reach
    // the real Postgres preview rows without unrelated missing-table failures.
    for table in SWEEP_TABLES {
        ch.query(&format!("CREATE TABLE IF NOT EXISTS tracelane.{} (tenant_id String, start_time DateTime, recorded_at DateTime, event_time DateTime, scored_at DateTime, captured_at DateTime, created_at DateTime, day Date) ENGINE=MergeTree ORDER BY tenant_id", table.label))
            .execute().await.unwrap();
    }
}

#[tokio::test]
#[ignore = "disposable PG:15438 and CH:18139; run serially"]
async fn empty_approval_previews_do_not_starve_later_tenant_cleanup() {
    use crate::entitlement_cache::b409_fixture::{
        builder_tenant, fresh_migrated_pool, seed_v3_then_v4,
    };
    let url = disposable_urls();
    empty_sweep_tables(&url).await;
    let pool = fresh_migrated_pool().await;
    seed_v3_then_v4(&pool).await;
    for _ in 0..3 {
        builder_tenant(&pool, Some("v3"), None).await;
    }
    let tenants = resolve_retentions(&pool).await.unwrap();
    let last = &tenants.last().unwrap().tenant_id;
    let id = uuid::Uuid::new_v4();
    let pg = pool.get().await.unwrap();
    pg.execute("INSERT INTO approvals(id,tenant_id,subject_kind,subject,requester_sub,args_fp,args_bytes,args_preview,status,created_at,expires_at) VALUES($1,$2::text::uuid,'model','old','requester','last-tenant',1,'STALE_CONTENT','consumed',clock_timestamp()-interval '10 years',clock_timestamp()-interval '10 years')",&[&id,&last]).await.unwrap();
    let mut policy = RetentionSweepPolicy::embedded();
    policy.max_mutations_per_run = 1;
    let mut run = SweepRun::new(policy);
    run_sweep_inner(&pool, &url, SweepMode::Enforce, &mut run)
        .await
        .unwrap();
    let preview: Option<String> = pg
        .query_one(
            "SELECT args_preview FROM approvals WHERE tenant_id=$1::text::uuid AND id=$2",
            &[&last, &id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        preview, None,
        "empty tenants must leave mutation capacity for the later stale row"
    );
    assert_eq!(run.mutations, 1);
}

#[tokio::test]
#[ignore = "disposable PG:15438 and CH:18139; run serially"]
async fn approval_previews_obey_resolved_retention_without_touching_newer_or_sibling_content() {
    use crate::entitlement_cache::b409_fixture::{
        builder_tenant, fresh_migrated_pool, seed_v3_then_v4,
    };
    let url = disposable_urls();
    empty_sweep_tables(&url).await;
    let pool = fresh_migrated_pool().await;
    seed_v3_then_v4(&pool).await;
    let alice = builder_tenant(&pool, Some("v3"), None).await;
    let bob = builder_tenant(&pool, Some("v3"), None).await;
    {
        let pg = pool.get().await.unwrap();
        let plan: serde_json::Value =
            serde_json::from_str(include_str!("../../../apps/web/db/plans.v3.json")).unwrap();
        pg.execute("INSERT INTO billing_policy(key,value) VALUES('data_controls',$1) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value", &[&plan["policy"]["data_controls"]]).await.unwrap();
        pg.execute(
            "INSERT INTO workspace_data_controls (tenant_id,retention_days,updated_by) VALUES ($1,7,'retention-test')",
            &[&alice],
        ).await.unwrap();
        for kind in ["tool", "model"] {
            for (tenant, age, preview) in [
                (alice, 8_i32, "alice-stale-content"),
                (alice, 1_i32, "alice-recent-content"),
                (bob, 8_i32, "bob-protected-content"),
            ] {
                pg.execute(
                    "INSERT INTO approvals (tenant_id,subject_kind,subject,requester_sub,args_fp,args_bytes,args_preview,status,created_at,expires_at) \
                     VALUES ($1,$2,'retention proof','requester',$3,64,$4,'consumed',clock_timestamp()-make_interval(days=>$5),clock_timestamp()-interval '1 hour')",
                    &[&tenant, &kind, &uuid::Uuid::new_v4().to_string(), &preview, &age],
                ).await.unwrap();
            }
        }
    }
    assert_eq!(
        resolve_retention(&pool, &alice.to_string()).await.unwrap(),
        Some(7)
    );
    assert!(
        resolve_retention(&pool, &bob.to_string())
            .await
            .unwrap()
            .unwrap()
            > 8
    );
    let mut dry = SweepRun::new(RetentionSweepPolicy::embedded());
    run_sweep_inner(&pool, &url, SweepMode::DryRun, &mut dry)
        .await
        .unwrap();
    let count: i64 = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT count(*) FROM approvals WHERE args_preview IS NOT NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 6, "dry-run cannot remove captured content");
    let mut enforce = SweepRun::new(RetentionSweepPolicy::embedded());
    run_sweep_inner(&pool, &url, SweepMode::Enforce, &mut enforce)
        .await
        .unwrap();
    let rows = pool.get().await.unwrap()
        .query("SELECT tenant_id,subject_kind,args_preview,created_at < clock_timestamp()-interval '7 days' AS older,status FROM approvals ORDER BY tenant_id,subject_kind,created_at", &[])
        .await.unwrap();
    assert_eq!(
        rows.len(),
        6,
        "clearing content must retain lifecycle metadata"
    );
    for row in rows {
        let tenant: uuid::Uuid = row.get("tenant_id");
        let preview: Option<String> = row.get("args_preview");
        let older: bool = row.get("older");
        let kind: &str = row.get("subject_kind");
        assert_eq!(row.get::<_, &str>("status"), "consumed");
        if tenant == alice && older {
            assert_eq!(preview, None, "expired {kind} preview must be cleared");
        } else if tenant == alice {
            assert_eq!(preview.as_deref(), Some("alice-recent-content"));
        } else {
            assert_eq!(tenant, bob);
            assert_eq!(preview.as_deref(), Some("bob-protected-content"));
        }
    }
}

#[tokio::test]
#[ignore = "disposable PG:15438 and CH:18139; run serially"]
async fn og38_spend_series_obeys_workspace_retention() {
    use crate::trace_reads::{ClickHouseTraceReader, TraceReadState};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let url = disposable_urls();
    let ch = retention_test_fixture::reset(&url).await;
    // Other retention tests use minimal schemas on this explicitly disposable
    // service. Restore the real aggregate DDL before proving its read path.
    ch.query("DROP TABLE IF EXISTS tracelane.spend_hourly")
        .execute()
        .await
        .unwrap();
    let ddl = crate::clickhouse_query::split_migration_statements(include_str!(
        "../../../infra/dev/clickhouse/schema.sql"
    ))
    .into_iter()
    .find(|s| s.contains("CREATE TABLE IF NOT EXISTS tracelane.spend_hourly\n"))
    .expect("checked-in spend_hourly DDL");
    ch.query(&ddl).execute().await.unwrap();
    let alice = uuid::Uuid::new_v4();
    let bob = uuid::Uuid::new_v4();
    let now = chrono::Utc::now().timestamp() / 3600 * 3600;
    let old = now - 40 * 86400;
    let recent = now - 3600;
    for (tenant, time, amount) in [
        (alice, old, 137_f64),
        (alice, recent, 3_f64),
        (bob, old, 251_f64),
    ] {
        ch.query("INSERT INTO tracelane.spend_hourly (tenant_id,bucket_hour,model,api_key_id,environment,service,cost_usd,priced_requests,unpriced_requests,requests) VALUES (?,fromUnixTimestamp(?),'fixture','','','',?,1,0,1)")
            .bind(tenant.to_string()).bind(time).bind(amount).execute().await.unwrap();
    }
    let cache = crate::entitlement_cache::EntitlementCache::new(Arc::new(move |tenant| {
        Box::pin(async move {
            Ok(crate::entitlement_cache::ResolvedEntitlements {
                queryable_days: if tenant == alice { 7 } else { 90 },
                ..crate::entitlement_cache::ResolvedEntitlements::deny_all()
            })
        })
    }));
    let reader =
        ClickHouseTraceReader::new(ch.clone()).with_entitlements(Some(Arc::new(cache)), None);
    let app = crate::trace_reads::routes(
        TraceReadState {
            reader: Arc::new(reader),
            rejections: Arc::new(crate::rejection_metrics::RejectionRegistry::new()),
        },
        axum::Router::new(),
    );
    for (tenant, since, expected_cost, expected_requests) in [
        (alice, old, 0_f64, 0_u64),
        (alice, recent, 3_f64, 1_u64),
        (bob, old, 251_f64, 1_u64),
    ] {
        let claims = crate::auth::Claims {
            tenant_id: tracelane_shared::TenantId::from_jwt_claim(tenant),
            ..crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer)
        };
        let _auth = crate::auth::test_claims::Guard::set(claims);
        let uri = format!(
            "/v1/spend/series?granularity=hour&since={}&until={}",
            crate::spend_spikes::iso(since),
            crate::spend_spikes::iso(since + 3600)
        );
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(uri)
                    .header("authorization", "Bearer fixture")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        let buckets = body["buckets"].as_array().expect("series buckets");
        let cost: f64 = buckets
            .iter()
            .map(|r| r["cost_usd"].as_f64().unwrap())
            .sum();
        let requests: u64 = buckets
            .iter()
            .map(|r| r["requests"].as_u64().unwrap())
            .sum();
        assert_eq!(
            cost, expected_cost,
            "retention-filtered costs for {tenant}: {body}"
        );
        assert_eq!(
            requests, expected_requests,
            "retention-filtered requests for {tenant}: {body}"
        );
    }
    let still_stored: u64 = ch
        .query("SELECT count() FROM tracelane.spend_hourly WHERE tenant_id = ?")
        .bind(alice.to_string())
        .fetch_one()
        .await
        .unwrap();
    assert_eq!(
        still_stored, 2,
        "the read cutoff applies before physical deletion"
    );
}

//! Ordinary synthetic outbox fixtures. No transport is invoked.
//! Each scenario owns its database; tests never delete shared state.
use super::{db, og23_tenant, test_pool};
use anyhow::Result;
use deadpool_postgres::Pool;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

async fn channel(pool: &Pool, label: &str) -> Result<(Uuid, Uuid)> {
    let tenant = og23_tenant(pool, label).await?;
    let id = Uuid::new_v4();
    let out = db::spend_alerts::create_channel(
        pool,
        &tenant,
        &db::spend_alerts::NewChannel {
            id,
            kind: "email",
            name: label.into(),
            target: "fixture@example.invalid".into(),
            secret_enc: None,
        },
        20,
        "fixture",
    )
    .await?;
    assert!(matches!(out, db::spend_alerts::CreateOutcome::Created(_)));
    Ok((*tenant.as_uuid(), id))
}

struct Seed<'a> {
    count: i32,
    age: i32,
    status: &'a str,
    due: bool,
    attempts: i32,
}
async fn seed(pool: &Pool, owner: (Uuid, Uuid), s: Seed<'_>) -> Result<Vec<Uuid>> {
    let rows = pool.get().await?.query(
        "INSERT INTO spend_alert_events (id,tenant_id,channel_id,dedup_key,payload,status,attempts,created_at,next_attempt_at) \
         SELECT gen_random_uuid(),$1,$2,$8::text || '-' || n,jsonb_build_object('tenant',$1::uuid::text,'number',n),$3,$4, \
         '2026-01-01'::timestamptz + make_interval(secs => $5::double precision), \
         CASE WHEN $6 THEN now()-interval '1 hour' ELSE now()+interval '1 hour' END \
         FROM generate_series(1,$7::int) n RETURNING id",
        &[&owner.0,&owner.1,&s.status,&s.attempts,&(s.age as f64),&s.due,&s.count,&Uuid::new_v4().to_string()],
    ).await?;
    Ok(rows.iter().map(|r| r.get(0)).collect())
}
fn pending(count: i32, age: i32) -> Seed<'static> {
    Seed {
        count,
        age,
        status: "pending",
        due: true,
        attempts: 0,
    }
}
fn first_round_present(actual: &[Uuid], expected: &[Uuid]) {
    for tenant in expected {
        assert!(
            actual.contains(tenant),
            "eligible tenant {tenant} omitted from first round: {actual:?}"
        );
    }
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn og24b_quiet_tenant_is_claimed_with_thousand_event_burst() -> Result<()> {
    let pool = test_pool().await?;
    let a = channel(&pool, "burst").await?;
    let b = channel(&pool, "quiet").await?;
    seed(&pool, a, pending(1000, 0)).await?;
    seed(&pool, b, pending(1, 100)).await?;
    let due = db::spend_alerts::claim_due(&pool, 50, 300).await?;
    assert_eq!(due.len(), 50);
    first_round_present(
        &due.iter().map(|d| d.channel.tenant_id).collect::<Vec<_>>(),
        &[a.0, b.0],
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn og24b_burst_order_batch_matrix_36_scenarios() -> Result<()> {
    let mut scenarios = 0;
    for volume in [1, 2, 50, 1000] {
        for limit in [2_i64, 10, 50] {
            for quiet_age in [-100, 0, 100] {
                let pool = test_pool().await?;
                let a = channel(&pool, "matrix-burst").await?;
                let b = channel(&pool, "matrix-quiet").await?;
                seed(&pool, a, pending(volume, 0)).await?;
                seed(&pool, b, pending(1, quiet_age)).await?;
                let due = db::spend_alerts::claim_due(&pool, limit, 300).await?;
                assert_eq!(due.len(), (i64::from(volume) + 1).min(limit) as usize);
                first_round_present(
                    &due.iter().map(|d| d.channel.tenant_id).collect::<Vec<_>>(),
                    &[a.0, b.0],
                );
                for d in due {
                    assert_eq!(d.payload["tenant"], d.channel.tenant_id.to_string());
                    assert_eq!(d.attempts, 0);
                    assert_eq!(d.channel.kind, "email");
                    assert_eq!(d.channel.target, "fixture@example.invalid");
                    assert!(d.channel.secret_enc.is_none());
                }
                scenarios += 1;
                eprintln!(
                    "og24b scenario {scenarios}: volume={volume} limit={limit} quiet_age={quiet_age} passed"
                );
            }
        }
    }
    assert_eq!(scenarios, 36);
    Ok(())
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn og24b_eligibility_attempt_matrix_12_scenarios() -> Result<()> {
    let mut scenarios = 0;
    for status in ["pending", "delivered", "failed"] {
        for due in [false, true] {
            for attempts in [0, 7] {
                let pool = test_pool().await?;
                let a = channel(&pool, "eligibility").await?;
                let ids = seed(
                    &pool,
                    a,
                    Seed {
                        count: 3,
                        age: 0,
                        status,
                        due,
                        attempts,
                    },
                )
                .await?;
                let claimed = db::spend_alerts::claim_due(&pool, 50, 300).await?;
                let eligible = status == "pending" && due;
                assert_eq!(claimed.len(), if eligible { 3 } else { 0 });
                for c in &claimed {
                    assert_eq!(c.attempts, attempts);
                    assert!(ids.contains(&c.event_id));
                    assert_eq!(c.channel.tenant_id, a.0);
                }
                let stored = pool
                    .get()
                    .await?
                    .query(
                        "SELECT status,attempts FROM spend_alert_events WHERE tenant_id=$1",
                        &[&a.0],
                    )
                    .await?;
                assert_eq!(stored.len(), 3);
                assert!(
                    stored
                        .iter()
                        .all(|r| r.get::<_, String>(0) == status && r.get::<_, i32>(1) == attempts)
                );
                scenarios += 1;
                eprintln!(
                    "og24b eligibility {scenarios}: status={status} due={due} attempts={attempts} passed"
                );
            }
        }
    }
    assert_eq!(scenarios, 12);
    Ok(())
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn og24b_empty_and_zero_limit_do_not_lease() -> Result<()> {
    let pool = test_pool().await?;
    assert!(
        db::spend_alerts::claim_due(&pool, 50, 300)
            .await?
            .is_empty()
    );
    let a = channel(&pool, "zero-limit").await?;
    seed(&pool, a, pending(1, 0)).await?;
    assert!(db::spend_alerts::claim_due(&pool, 0, 300).await?.is_empty());
    assert_eq!(db::spend_alerts::claim_due(&pool, 1, 300).await?.len(), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn og24b_claimed_rows_are_leased_without_delivery() -> Result<()> {
    let pool = test_pool().await?;
    let a = channel(&pool, "lease").await?;
    seed(&pool, a, pending(2, 0)).await?;
    assert_eq!(db::spend_alerts::claim_due(&pool, 50, 300).await?.len(), 2);
    assert!(
        db::spend_alerts::claim_due(&pool, 50, 300)
            .await?
            .is_empty()
    );
    let rows=pool.get().await?.query("SELECT status,attempts,next_attempt_at>now() FROM spend_alert_events WHERE tenant_id=$1", &[&a.0]).await?;
    assert!(rows.iter().all(|r| r.get::<_, String>(0) == "pending"
        && r.get::<_, i32>(1) == 0
        && r.get::<_, bool>(2)));
    Ok(())
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn og24b_concurrent_claimers_never_share_an_event() -> Result<()> {
    let pool = test_pool().await?;
    for label in ["concurrent-a", "concurrent-b"] {
        let owner = channel(&pool, label).await?;
        seed(&pool, owner, pending(50, 0)).await?;
    }
    let (a, b) = tokio::join!(
        db::spend_alerts::claim_due(&pool, 50, 300),
        db::spend_alerts::claim_due(&pool, 50, 300)
    );
    let (a, b) = (a?, b?);
    assert_eq!(a.len() + b.len(), 100);
    let ids: BTreeSet<_> = a.iter().chain(&b).map(|d| d.event_id).collect();
    assert_eq!(ids.len(), 100);
    Ok(())
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn og24b_locked_row_does_not_block_other_tenant() -> Result<()> {
    let pool = test_pool().await?;
    let a = channel(&pool, "locked").await?;
    let b = channel(&pool, "unlocked").await?;
    let ids = seed(&pool, a, pending(1, 0)).await?;
    seed(&pool, b, pending(1, 100)).await?;
    let mut connection = pool.get().await?;
    let tx = connection.transaction().await?;
    tx.query_one(
        "SELECT id FROM spend_alert_events WHERE id=$1 AND tenant_id=$2 FOR UPDATE",
        &[&ids[0], &a.0],
    )
    .await?;
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        db::spend_alerts::claim_due(&pool, 50, 300),
    )
    .await??;
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].channel.tenant_id, b.0);
    tx.rollback().await?;
    assert_eq!(db::spend_alerts::claim_due(&pool, 50, 300).await?.len(), 1);
    Ok(())
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn og24b_finite_single_row_queues_progress_in_subsequent_batch() -> Result<()> {
    let pool = test_pool().await?;
    let mut tenants = Vec::new();
    for i in 0..12 {
        let owner = channel(&pool, &format!("round-{i}")).await?;
        seed(&pool, owner, pending(1, i)).await?;
        tenants.push(owner.0);
    }
    let first = db::spend_alerts::claim_due(&pool, 10, 300).await?;
    let second = db::spend_alerts::claim_due(&pool, 10, 300).await?;
    assert_eq!((first.len(), second.len()), (10, 2));
    let counts = first
        .iter()
        .chain(&second)
        .fold(BTreeMap::new(), |mut m, d| {
            *m.entry(d.channel.tenant_id).or_insert(0) += 1;
            m
        });
    assert_eq!(counts.len(), tenants.len());
    assert!(counts.values().all(|count| *count == 1));
    Ok(())
}

/// The contract is per-batch sharing, not eventual service for >limit active tenants.
/// Keep enough ordinary backlog that the first claimed tenant still has due rows.
#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn og24b_51_tenant_backlogs_share_each_50_slot_batch() -> Result<()> {
    let pool = test_pool().await?;
    for i in 0..51 {
        let owner = channel(&pool, &format!("oversubscribed-{i}")).await?;
        seed(&pool, owner, pending(3, i)).await?;
    }
    let mut previously_claimed = BTreeSet::new();
    for batch in 0..2 {
        let claimed = db::spend_alerts::claim_due(&pool, 50, 300).await?;
        assert_eq!(claimed.len(), 50);
        let tenants: BTreeSet<_> = claimed.iter().map(|d| d.channel.tenant_id).collect();
        assert_eq!(
            tenants.len(),
            50,
            "batch {batch}: a tenant took a second slot before the first round filled"
        );
        for row in claimed {
            assert!(
                previously_claimed.insert(row.event_id),
                "unexpired lease claimed twice"
            );
        }
    }
    // Deliberately no all-tenants-visited assertion: ordering within each round does
    // not persist a cross-batch rotation cursor, and makes no starvation-free promise.
    Ok(())
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn og24b_multirow_tenants_fill_later_rounds_and_unused_capacity() -> Result<()> {
    for (a_rows, b_rows, limit, a_expected, b_expected) in [
        (2, 2, 4_i64, 2, 2),
        (3, 3, 4, 2, 2),
        (3, 3, 5, 3, 2),
        (2, 10, 8, 2, 6),
        (10, 2, 8, 6, 2),
    ] {
        let pool = test_pool().await?;
        let a = channel(&pool, "later-round-a").await?;
        let b = channel(&pool, "later-round-b").await?;
        let mut a_ids = seed(&pool, a, pending(a_rows, 0)).await?;
        let mut b_ids = seed(&pool, b, pending(b_rows, 100)).await?;
        a_ids.sort_unstable();
        b_ids.sort_unstable();
        let due = db::spend_alerts::claim_due(&pool, limit, 300).await?;
        assert_eq!(
            due.len(),
            limit as usize,
            "rounds must fill available capacity"
        );
        assert_eq!(
            due.iter().filter(|d| d.channel.tenant_id == a.0).count(),
            a_expected
        );
        assert_eq!(
            due.iter().filter(|d| d.channel.tenant_id == b.0).count(),
            b_expected
        );
        let expected: BTreeSet<_> = a_ids
            .into_iter()
            .take(a_expected)
            .chain(b_ids.into_iter().take(b_expected))
            .collect();
        assert_eq!(
            due.iter().map(|d| d.event_id).collect::<BTreeSet<_>>(),
            expected,
            "claim the oldest eligible IDs within each round; RETURNING order is unspecified"
        );
        eprintln!(
            "og24b later rounds: {a_rows}+{b_rows} limit={limit}, split={a_expected}+{b_expected} passed"
        );
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn og24b_ineligible_predecessors_do_not_consume_tenant_turns() -> Result<()> {
    for (status, due) in [("delivered", true), ("failed", true), ("pending", false)] {
        let pool = test_pool().await?;
        let a = channel(&pool, "eligible-burst").await?;
        let b = channel(&pool, "eligible-after-ineligible").await?;
        seed(&pool, a, pending(100, 0)).await?;
        let ineligible = seed(
            &pool,
            b,
            Seed {
                count: 3,
                age: -100,
                status,
                due,
                attempts: 0,
            },
        )
        .await?;
        let eligible = seed(&pool, b, pending(1, 100)).await?;
        let before = leases(&pool, b.0, &ineligible).await?;
        let claimed = db::spend_alerts::claim_due(&pool, 2, 300).await?;
        assert_eq!(claimed.len(), 2);
        first_round_present(
            &claimed
                .iter()
                .map(|d| d.channel.tenant_id)
                .collect::<Vec<_>>(),
            &[a.0, b.0],
        );
        assert!(claimed.iter().any(|d| d.event_id == eligible[0]));
        assert!(claimed.iter().all(|d| !ineligible.contains(&d.event_id)));
        assert_eq!(
            leases(&pool, b.0, &ineligible).await?,
            before,
            "ineligible leases must be untouched"
        );
        eprintln!("og24b excluded predecessor: status={status}, due={due} passed");
    }
    Ok(())
}

async fn leases(
    pool: &Pool,
    tenant: Uuid,
    ids: &[Uuid],
) -> Result<BTreeMap<Uuid, chrono::DateTime<chrono::Utc>>> {
    let rows = pool
        .get()
        .await?
        .query(
            "SELECT id,next_attempt_at FROM spend_alert_events WHERE tenant_id=$1",
            &[&tenant],
        )
        .await?;
    Ok(rows
        .iter()
        .filter_map(|r| {
            let id: Uuid = r.get(0);
            ids.contains(&id).then(|| (id, r.get(1)))
        })
        .collect())
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn og24b_equal_timestamps_choose_fixed_ids_within_each_tenant() -> Result<()> {
    let pool = test_pool().await?;
    let a = channel(&pool, "fixed-order-a").await?;
    let b = channel(&pool, "fixed-order-b").await?;
    for (owner, numbers) in [(a, [3_u128, 1, 2]), (b, [13, 11, 12])] {
        for number in numbers {
            let id = Uuid::from_u128(number);
            pool.get().await?.execute(
                "INSERT INTO spend_alert_events (id,tenant_id,channel_id,dedup_key,payload,created_at,next_attempt_at) \
                 VALUES ($1,$2,$3,$4,'{}','2026-01-01'::timestamptz,now()-interval '1 hour')",
                &[&id,&owner.0,&owner.1,&format!("fixed-{number}")]
            ).await?;
        }
    }
    let due = db::spend_alerts::claim_due(&pool, 4, 300).await?;
    let expected: BTreeSet<_> = [1_u128, 2, 11, 12]
        .into_iter()
        .map(Uuid::from_u128)
        .collect();
    assert_eq!(
        due.iter().map(|d| d.event_id).collect::<BTreeSet<_>>(),
        expected
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires task-owned isolated Postgres"]
async fn og24b_expired_lease_and_failed_delivery_retry_preserve_event_identity() -> Result<()> {
    let pool = test_pool().await?;
    let owner = channel(&pool, "retry").await?;
    let ids = seed(&pool, owner, pending(1, 0)).await?;
    let first = db::spend_alerts::claim_due(&pool, 1, 1).await?;
    assert_eq!(first[0].event_id, ids[0]);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let expired = db::spend_alerts::claim_due(&pool, 1, 300).await?;
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].event_id, ids[0]);
    assert_eq!(expired[0].attempts, 0, "claiming is not a delivery attempt");
    db::spend_alerts::record_outcome(
        &pool,
        ids[0],
        Err("synthetic receiver unavailable".into()),
        0,
        false,
    )
    .await?;
    let retry = db::spend_alerts::claim_due(&pool, 1, 300).await?;
    assert_eq!(retry.len(), 1);
    assert_eq!(retry[0].event_id, ids[0]);
    assert_eq!(retry[0].attempts, 1);
    db::spend_alerts::record_outcome(&pool, ids[0], Ok(()), 0, false).await?;
    assert!(db::spend_alerts::claim_due(&pool, 1, 300).await?.is_empty());
    let row = pool.get().await?.query_one(
        "SELECT status,attempts,last_error FROM spend_alert_events WHERE tenant_id=$1 AND id=$2",
        &[&owner.0,&ids[0]]).await?;
    assert_eq!(row.get::<_, String>(0), "delivered");
    assert_eq!(row.get::<_, i32>(1), 2);
    assert!(row.get::<_, Option<String>>(2).is_none());
    Ok(())
}

#[test]
fn og24b_pure_fixture_fairness_assertion_mutation() {
    let expected = [Uuid::from_u128(1), Uuid::from_u128(2)];
    let actual = if std::env::var_os("TRACELANE_TEST_INVALID_FAIR_CLAIM_RESULT").is_some() {
        vec![expected[0], expected[0]]
    } else {
        expected.to_vec()
    };
    first_round_present(&actual, &expected);
}

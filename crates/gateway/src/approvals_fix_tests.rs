//! FIX reproductions use the production approval operations and isolated migrated Postgres.
use super::*;
use std::sync::Arc;

async fn fixture() -> (DbPool, Claims) {
    crate::tool_fingerprint::init_from_existing_pepper(&"07".repeat(32)).unwrap();
    let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
    let claims = add_tenant(&pool).await;
    (pool, claims)
}

async fn add_tenant(pool: &DbPool) -> Claims {
    let tenant = TenantId::from_jwt_claim(Uuid::new_v4());
    pool.get()
        .await
        .unwrap()
        .execute(
            "INSERT INTO tenants(id,workos_org_id,name) VALUES($1,$2,'Approval FIX regression')",
            &[tenant.as_uuid(), &format!("org_{tenant}")],
        )
        .await
        .unwrap();
    Claims {
        tenant_id: tenant,
        sub: format!("approval-fix:{}", Uuid::new_v4()),
        ..crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer)
    }
}

fn request<'a>(kind: &'static str, body: &'a Value) -> Request<'a> {
    Request {
        kind,
        server: None,
        subject: "protected-operation",
        rule: None,
        ttl_secs: crate::mcp_policy::settings()
            .unwrap()
            .approvals
            .default_ttl_secs,
        body,
        trace_id: Uuid::new_v4(),
    }
}

async fn approve(pool: &DbPool, claims: &Claims, id: Uuid) {
    assert_eq!(pool.get().await.unwrap().execute(
        "UPDATE approvals SET status='approved',decided_by='independent-human',grant_expires_at=clock_timestamp()+interval '1 hour' WHERE tenant_id=$1 AND id=$2 AND status='pending'",
        &[claims.tenant_id.as_uuid(), &id],
    ).await.unwrap(), 1);
}

async fn recreates_terminal(status: &str) {
    let (pool, claims) = fixture().await;
    for kind in ["tool", "model"] {
        let body = json!({"params":{"arguments":{"operation":kind}}});
        let req = request(kind, &body);
        let first = find_or_create(&pool, &claims, &req, None).await.unwrap();
        assert_eq!(first.status, "pending");
        if status == "consumed" {
            approve(&pool, &claims, first.id).await;
            assert_eq!(
                consume(&pool, &claims, first.id).await.unwrap().as_deref(),
                Some("independent-human")
            );
        } else {
            pool.get().await.unwrap().execute(
                "UPDATE approvals SET status=$3,expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2",
                &[claims.tenant_id.as_uuid(), &first.id, &status],
            ).await.unwrap();
        }
        let second = find_or_create(&pool, &claims, &req, None).await.unwrap();
        assert_ne!(
            first.id, second.id,
            "{kind}: terminal {status} must not poison future requests"
        );
        assert_eq!(second.status, "pending");
        assert!(second.expires_at > Utc::now());
        let rows = pool.get().await.unwrap().query(
            "SELECT id,status FROM approvals WHERE tenant_id=$1 AND subject_kind=$2 ORDER BY created_at",
            &[claims.tenant_id.as_uuid(), &kind],
        ).await.unwrap();
        assert_eq!(rows.len(), 2, "terminal history must remain");
        assert_eq!(rows[0].get::<_, String>(1), status);
        assert_eq!(rows[1].get::<_, String>(1), "pending");
    }
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn approval_same_tool_and_model_after_consumption_create_new_pending() {
    recreates_terminal("consumed").await;
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn approval_same_tool_and_model_after_expiry_create_new_pending() {
    recreates_terminal("expired").await;
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn approval_same_tool_and_model_after_denial_create_new_pending() {
    recreates_terminal("denied").await;
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn approval_expired_unswept_row_does_not_poison_identical_retry() {
    let (pool, claims) = fixture().await;
    let body = json!({"argument":"same"});
    let req = request("model", &body);
    let first = find_or_create(&pool, &claims, &req, None).await.unwrap();
    pool.get().await.unwrap().execute(
        "UPDATE approvals SET expires_at=clock_timestamp()-interval '1 second' WHERE tenant_id=$1 AND id=$2",
        &[claims.tenant_id.as_uuid(), &first.id],
    ).await.unwrap();
    let second = find_or_create(&pool, &claims, &req, None).await.unwrap();
    assert_ne!(first.id, second.id);
    assert_eq!(second.status, "pending");
    assert!(second.expires_at > Utc::now());
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn approval_concurrent_identical_requests_share_one_pending_and_one_consumption() {
    let (pool, claims) = fixture().await;
    for kind in ["tool", "model"] {
        let body = json!({"kind":kind,"same_arguments":true});
        let req = request(kind, &body);
        let (left, right) = tokio::join!(
            find_or_create(&pool, &claims, &req, None),
            find_or_create(&pool, &claims, &req, None)
        );
        let id = left.unwrap().id;
        assert_eq!(id, right.unwrap().id);
        let pending: i64 = pool.get().await.unwrap().query_one(
            "SELECT count(*) FROM approvals WHERE tenant_id=$1 AND subject_kind=$2 AND status='pending'",
            &[claims.tenant_id.as_uuid(), &kind],
        ).await.unwrap().get(0);
        assert_eq!(pending, 1);
        approve(&pool, &claims, id).await;
        let (left, right) = tokio::join!(consume(&pool, &claims, id), consume(&pool, &claims, id));
        assert_eq!(
            [left.unwrap(), right.unwrap()]
                .iter()
                .filter(|r| r.is_some())
                .count(),
            1
        );
        let row = pool
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT status,consumed_at IS NOT NULL FROM approvals WHERE tenant_id=$1 AND id=$2",
                &[claims.tenant_id.as_uuid(), &id],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, String>(0), "consumed");
        assert!(row.get::<_, bool>(1));
        let audits: i64 = pool.get().await.unwrap().query_one(
            "SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id=$1 AND target_id=$2 AND action='approval.consume'",
            &[claims.tenant_id.as_uuid(), &id.to_string()],
        ).await.unwrap().get(0);
        assert_eq!(audits, 1);
    }
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn approval_expiring_while_consume_waits_cannot_execute() {
    let (pool, claims) = fixture().await;
    let body = json!({"argument":"expires while locked"});
    let first = find_or_create(&pool, &claims, &request("model", &body), None)
        .await
        .unwrap();
    approve(&pool, &claims, first.id).await;
    let mut locker = pool.get().await.unwrap();
    locker.execute(
        "UPDATE approvals SET grant_expires_at=clock_timestamp()+interval '2 seconds' WHERE tenant_id=$1 AND id=$2",
        &[claims.tenant_id.as_uuid(), &first.id],
    ).await.unwrap();
    let tx = locker.transaction().await.unwrap();
    tx.query_one(
        "SELECT id FROM approvals WHERE tenant_id=$1 AND id=$2 FOR UPDATE",
        &[claims.tenant_id.as_uuid(), &first.id],
    )
    .await
    .unwrap();
    let consuming = {
        let pool = pool.clone();
        let claims = claims.clone();
        tokio::spawn(async move { consume(&pool, &claims, first.id).await })
    };
    let observer = pool.get().await.unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let waiting: bool = observer.query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%approvals%' AND cardinality(pg_blocking_pids(pid)) > 0)",
                &[],
            ).await.unwrap().get(0);
            if waiting { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("consumer must start and block before its grant expires");
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            let expired: bool = observer.query_one(
                "SELECT grant_expires_at<=clock_timestamp() FROM approvals WHERE tenant_id=$1 AND id=$2",
                &[claims.tenant_id.as_uuid(), &first.id],
            ).await.unwrap().get(0);
            if expired { break; }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }).await.unwrap();
    tx.commit().await.unwrap();
    let consumed = consuming.await.unwrap().unwrap();
    assert!(
        consumed.is_none(),
        "a transaction-start timestamp must not resurrect an expired grant after a lock wait"
    );
    let row = observer
        .query_one(
            "SELECT status,consumed_at FROM approvals WHERE tenant_id=$1 AND id=$2",
            &[claims.tenant_id.as_uuid(), &first.id],
        )
        .await
        .unwrap();
    assert_eq!(row.get::<_, String>(0), "approved");
    assert!(row.get::<_, Option<DateTime<Utc>>>(1).is_none());
}

#[test]
fn approval_wake_reaches_every_waiter_on_same_id() {
    let tenant = Uuid::new_v4();
    let id = Uuid::new_v4();
    let count = crate::mcp_policy::settings()
        .unwrap()
        .approvals
        .max_held_per_workspace;
    let waiters: Vec<_> = (0..count).map(|_| hold(tenant, id).unwrap()).collect();
    wake(id);
    for waiter in &waiters {
        assert!(
            waiter.receiver.has_changed().unwrap(),
            "every held caller must receive the decision"
        );
    }
    drop(waiters);
    assert_eq!(held_now(tenant), 0);
    assert!(!holds().lock().signals.contains_key(&id));
}

#[test]
fn approval_concurrent_hold_drops_release_all_signal_entries() {
    let tenant = Uuid::new_v4();
    let count = crate::mcp_policy::settings()
        .unwrap()
        .approvals
        .max_held_per_workspace;
    // Distinct tenant/id sets keep this test independent of other parallel hold tests.
    for same_id in [true, false] {
        for _ in 0..100 {
            let shared_id = Uuid::new_v4();
            let ids: Vec<_> = (0..count)
                .map(|_| if same_id { shared_id } else { Uuid::new_v4() })
                .collect();
            let waiters: Vec<_> = ids.iter().map(|id| hold(tenant, *id).unwrap()).collect();
            let barrier = Arc::new(std::sync::Barrier::new(count));
            std::thread::scope(|scope| {
                for waiter in waiters {
                    let barrier = barrier.clone();
                    scope.spawn(move || {
                        barrier.wait();
                        drop(waiter);
                    });
                }
            });
            let state = holds().lock();
            assert!(!state.tenants.contains_key(&tenant));
            assert!(
                ids.iter().all(|id| !state.signals.contains_key(id)),
                "dropped receivers must not leave signal senders behind"
            );
            assert_eq!(state.total, state.tenants.values().sum::<usize>());
        }
    }
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn approval_preview_respects_workspace_key_and_zdr_capture_constraints() {
    let (pool, claims) = fixture().await;
    let mut state =
        crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
    state.pg = Some(pool.clone());
    for (case, workspace, key_off, zdr, stored) in [
        ("workspace-off", false, false, false, false),
        ("key-off", true, true, false, false),
        ("zdr", true, false, true, false),
        ("enabled", true, false, false, true),
    ] {
        let mut caller = claims.clone();
        if key_off {
            caller.key_capture = Some(crate::db::data_controls::KeyCapture {
                input: Some(false),
                output: None,
            });
        }
        let mut ent = crate::entitlement_cache::ResolvedEntitlements::deny_all();
        ent.content_capture.input = workspace;
        let ent = Arc::new(ent);
        let mut headers = axum::http::HeaderMap::new();
        if zdr {
            headers.insert("x-tracelane-zdr", "true".parse().unwrap());
        }
        let body = json!({"case":case,"customer_content":"retention constrained content"});
        let denial = gate(
            &state,
            &caller,
            request("model", &body),
            None,
            &headers,
            Some(&ent),
        )
        .await
        .unwrap_err();
        assert_eq!(denial.code, "approval_required");
        let id = Uuid::parse_str(
            denial
                .detail
                .iter()
                .find(|(key, _)| *key == "approval_id")
                .unwrap()
                .1
                .as_str()
                .unwrap(),
        )
        .unwrap();
        let preview: Option<String> = pool
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT args_preview FROM approvals WHERE tenant_id=$1 AND id=$2",
                &[claims.tenant_id.as_uuid(), &id],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(preview.is_some(), stored, "capture case {case}");
        if let Some(preview) = preview {
            assert!(preview.contains("retention constrained content"));
        }
    }
}

#[tokio::test]
#[ignore = "requires disposable local Postgres"]
async fn approval_pending_capacity_refuses_without_row_or_notification_and_is_tenant_scoped() {
    let (pool, claims) = fixture().await;
    let other = add_tenant(&pool).await;
    let mut state =
        crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
    state.pg = Some(pool.clone());
    let seed: Value = serde_json::from_str(include_str!("../mcp_policy.v1.json")).unwrap();
    // The old schema has no pending cap; its existing held cap supplies the RED workload.
    let cap = seed["approvals"]["max_pending_per_workspace"]
        .as_i64()
        .unwrap_or_else(|| {
            i64::try_from(
                crate::mcp_policy::settings()
                    .unwrap()
                    .approvals
                    .max_held_per_workspace,
            )
            .unwrap()
        });
    assert!(cap > 0);
    pool.get().await.unwrap().execute(
        "INSERT INTO approvals(tenant_id,subject_kind,subject,requester_sub,args_fp,args_bytes,expires_at) SELECT $1,'model','seed',$2,'seed-'||n::text,0,clock_timestamp()+interval '1 hour' FROM generate_series(1,$3::bigint) n",
        &[claims.tenant_id.as_uuid(), &claims.sub, &(cap - 1)],
    ).await.unwrap();
    let channel = crate::db::spend_alerts::NewChannel {
        id: Uuid::new_v4(),
        kind: "email",
        name: "Capacity proof".into(),
        target: "approval-fixture@example.invalid".into(),
        secret_enc: None,
    };
    crate::db::spend_alerts::create_channel(&pool, &claims.tenant_id, &channel, 1, "test")
        .await
        .unwrap();
    let headers = axum::http::HeaderMap::new();
    let body = json!({"capacity":"last available slot"});
    let below = gate(
        &state,
        &claims,
        request("model", &body),
        None,
        &headers,
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(below.code, "approval_required");
    let extra = json!({"capacity":"over cap"});
    let over = gate(
        &state,
        &claims,
        request("model", &extra),
        None,
        &headers,
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(over.status, 429);
    assert_eq!(over.code, "approval_capacity");
    assert_eq!(
        over.retry_after_secs,
        Some(
            crate::mcp_policy::settings()
                .unwrap()
                .approvals
                .capacity_retry_secs
        )
    );
    let client = pool.get().await.unwrap();
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM approvals WHERE tenant_id=$1",
            &[claims.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, cap);
    let events: i64 = client
        .query_one(
            "SELECT count(*) FROM spend_alert_events WHERE tenant_id=$1",
            &[claims.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        events, 1,
        "over-cap requests must not enqueue a notification"
    );
    let retry = gate(
        &state,
        &claims,
        request("model", &body),
        None,
        &headers,
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(
        retry.code, "approval_required",
        "deduplicated retry uses no new capacity"
    );
    let unaffected = gate(
        &state,
        &other,
        request("model", &extra),
        None,
        &headers,
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(unaffected.code, "approval_required");
    let count: i64 = client
        .query_one(
            "SELECT count(*) FROM approvals WHERE tenant_id=$1",
            &[other.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 1);
}

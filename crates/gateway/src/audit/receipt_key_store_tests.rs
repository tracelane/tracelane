//! Ordinary append/copy/read regression in fresh, retained, task-owned stores.
//! No table reset, row alteration, publication, or server-setting change.
use super::*;

#[tokio::test]
#[ignore = "requires task-owned loopback Postgres and ClickHouse"]
async fn receipt_key_normal_append_copies_to_fresh_clickhouse_database() {
    let ch_url = std::env::var("CLICKHOUSE_TEST_URL").expect("task-owned ClickHouse URL required");
    let parsed = reqwest::Url::parse(&ch_url).unwrap();
    assert_eq!(parsed.scheme(), "http");
    assert_eq!(parsed.host_str(), Some("127.0.0.1"));
    assert_eq!(
        parsed.port(),
        Some(28125),
        "only the task-owned fixture endpoint is allowed"
    );
    assert!(parsed.username().is_empty() && parsed.password().is_none());
    assert_eq!(parsed.path(), "/");
    assert!(parsed.query().is_none() && parsed.fragment().is_none());
    assert!(
        std::env::var_os("TRACELANE_REKOR_URL").is_none(),
        "publication override must not be configured"
    );
    let pg_url = std::env::var("POSTGRES_TEST_URL").expect("task-owned Postgres URL required");
    let pg_config: tokio_postgres::Config = pg_url.parse().unwrap();
    assert!(
        matches!(pg_config.get_hosts(), [tokio_postgres::config::Host::Tcp(host)] if host == "127.0.0.1")
    );
    assert!(
        pg_config
            .get_hostaddrs()
            .iter()
            .all(std::net::IpAddr::is_loopback)
    );
    assert_eq!(pg_config.get_ports(), &[25432]);
    assert_eq!(pg_config.get_user(), Some("wave_test"));
    let pool = crate::entitlement_cache::b409_fixture::fresh_migrated_pool().await;
    let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
    crate::db::tenants::create(&pool, *tenant.as_uuid(), "synthetic-receipt-copy", "free")
        .await
        .unwrap();
    let database = format!("receipt_copy_{}", uuid::Uuid::new_v4().simple());
    let unscoped = ClickhouseClient::default().with_url(&ch_url);
    unscoped
        .query("CREATE DATABASE ?")
        .bind(clickhouse::sql::Identifier(&database))
        .execute()
        .await
        .unwrap();
    let ch = unscoped.with_database(&database);
    ch.query("CREATE TABLE audit_log (tenant_id String, seq UInt64, event_time DateTime64(6,'UTC'), event_type String, actor String, payload String DEFAULT '{}', prev_hash String DEFAULT '', row_hash String, rekor_entry_id Nullable(String), signature String DEFAULT '', signing_pubkey String DEFAULT '') ENGINE = ReplacingMergeTree(event_time) ORDER BY (tenant_id,seq)").execute().await.unwrap();
    let mut chain = AuditChain::with_pg_pool(0, None, None, Some(pool.clone())).unwrap();
    chain.clickhouse_client = Some(ch.clone());
    assert!(chain.platform_public_key().is_none());
    for ordinal in 0..2 {
        chain
            .append(AuditEvent {
                tenant_id: tenant.clone(),
                event_type: "request",
                actor: "synthetic-receipt-copy".into(),
                payload: json!({"ordinal":ordinal}),
            })
            .await
            .unwrap();
    }
    let canonical = crate::db::ledger::read_rows_from(&pool, &tenant, 0, 10)
        .await
        .unwrap();
    #[derive(Debug, serde::Deserialize, clickhouse::Row)]
    struct Copied {
        seq: u64,
        event_type: String,
        actor: String,
        payload: String,
        prev_hash: String,
        row_hash: String,
        signature: String,
        signing_pubkey: String,
    }
    let copied = ch.query("SELECT seq,event_type,actor,payload,prev_hash,row_hash,signature,signing_pubkey FROM audit_log FINAL WHERE tenant_id=? ORDER BY seq")
        .bind(tenant.to_string()).fetch_all::<Copied>().await.unwrap();
    assert_eq!(canonical.len(), 2);
    assert_eq!(copied.len(), 2);
    assert_eq!(canonical[1].seq, canonical[0].seq + 1);
    assert_ne!(canonical[0].payload, canonical[1].payload);
    assert_ne!(canonical[0].row_hash, canonical[1].row_hash);
    assert_eq!(canonical[1].prev_hash, canonical[0].row_hash);
    // Compare sequence, type, actor, payload, previous/current hash and unsigned status.
    // Timestamp and optional publication ID are not comparison coverage in this fixture.
    for (pg, ch) in canonical.iter().zip(copied) {
        assert_eq!(ch.seq, pg.seq);
        assert_eq!(ch.event_type, pg.event_type);
        assert_eq!(ch.actor, pg.actor);
        assert_eq!(ch.payload, pg.payload);
        assert_eq!(ch.prev_hash, pg.prev_hash);
        assert_eq!(ch.row_hash, pg.row_hash);
        assert!(ch.signature.is_empty() && ch.signing_pubkey.is_empty());
    }
    println!("retained task-owned ClickHouse fixture database: {database}");
}

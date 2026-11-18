//! Copy recovery assertions use the production HTTP client, reconcile and INSERT path.
//! Only the ClickHouse HTTP boundary is replaced; canonical reads use real Postgres.
use super::*;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone)]
struct CopySink {
    tenant: String,
    expected: BTreeMap<u64, Vec<u8>>,
    present: Arc<Mutex<BTreeSet<u64>>>,
}

fn string_bytes(out: &mut Vec<u8>, value: &str) {
    let mut len = value.len();
    while len >= 128 {
        out.push((len as u8 & 0x7f) | 0x80);
        len >>= 7;
    }
    out.push(len as u8);
    out.extend_from_slice(value.as_bytes());
}

// Independent RowBinary fixture encoding: INSERTs must contain the exact durable
// fields, including canonical payload bytes, tenant, sequence, and both hashes.
fn row_bytes(row: &AuditLogRow) -> Vec<u8> {
    let mut out = Vec::new();
    string_bytes(&mut out, &row.tenant_id);
    out.extend_from_slice(&row.seq.to_le_bytes());
    out.extend_from_slice(&row.event_time.to_le_bytes());
    for value in [
        &row.event_type,
        &row.actor,
        &row.payload,
        &row.prev_hash,
        &row.row_hash,
    ] {
        string_bytes(&mut out, value);
    }
    out.push(u8::from(row.rekor_entry_id.is_none()));
    if let Some(value) = &row.rekor_entry_id {
        string_bytes(&mut out, value);
    }
    string_bytes(&mut out, &row.signature);
    string_bytes(&mut out, &row.signing_pubkey);
    out
}

impl wiremock::Respond for CopySink {
    fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
        let query = request
            .url
            .query_pairs()
            .find(|(name, _)| name == "query")
            .unwrap()
            .1
            .into_owned();
        if query.starts_with("INSERT INTO audit_log(") {
            let mut body = request.body.as_slice();
            let mut parsed = BTreeSet::new();
            while !body.is_empty() {
                let Some((seq, bytes)) = self
                    .expected
                    .iter()
                    .find(|(_, bytes)| body.starts_with(bytes))
                else {
                    return wiremock::ResponseTemplate::new(400)
                        .set_body_string("INSERT differs from canonical Postgres rows");
                };
                parsed.insert(*seq);
                body = &body[bytes.len()..];
            }
            self.present.lock().extend(parsed);
            return wiremock::ResponseTemplate::new(200);
        }
        assert!(
            query.contains(&format!("tenant_id = '{}'", self.tenant)),
            "unscoped copy read: {query}"
        );
        let bytes = if query.starts_with("SELECT count() AS n, max(seq) AS hi") {
            let present = self.present.lock();
            [present.len() as u64, present.last().copied().unwrap_or(0)]
                .into_iter()
                .flat_map(u64::to_le_bytes)
                .collect()
        } else if query.contains("FROM audit_anchor_records") {
            // No anchors exist before the missed hook is recovered.
            vec![0; 9]
        } else if query.starts_with(&format!("SELECT {COPY_ROW_COLUMNS}")) {
            // The durable head is the final canonical row, so the copy has no
            // rows beyond it for reconcile rule 2 to adopt.
            assert!(query.contains(&format!(
                "seq > {} ",
                self.expected.last_key_value().unwrap().0
            )));
            Vec::new()
        } else {
            panic!("unexpected copy query: {query}");
        };
        wiremock::ResponseTemplate::new(200).set_body_bytes(bytes)
    }
}

#[test]
fn copy_sink_rejected_insert_cannot_publish_rows() {
    use wiremock::Respond;
    let sink = CopySink {
        tenant: "synthetic".into(),
        expected: BTreeMap::from([(0, vec![1]), (1, vec![2]), (2, vec![3])]),
        present: Arc::new(Mutex::new(BTreeSet::new())),
    };
    let mut request = wiremock::Request {
        url: "http://localhost/?query=INSERT%20INTO%20audit_log(x)%20FORMAT%20RowBinary"
            .parse()
            .unwrap(),
        method: "POST".parse().unwrap(),
        headers: Default::default(),
        body: vec![1, 2, 3, 255],
    };
    sink.respond(&request);
    assert!(
        sink.present.lock().is_empty(),
        "a rejected INSERT must not publish rows"
    );
    request.body.pop();
    sink.respond(&request);
    assert_eq!(*sink.present.lock(), BTreeSet::from([0, 1, 2]));
}

pub(crate) async fn assert_restart_recovers_copy(
    pool: &deadpool_postgres::Pool,
    tenant: &TenantId,
) {
    let canonical = crate::db::ledger::read_rows_from(pool, tenant, 0, 10)
        .await
        .unwrap();
    assert_eq!(
        canonical.len(),
        3,
        "fixture must cover an interior copy hole"
    );
    for initial in [vec![], vec![0, 2]] {
        let sink = CopySink {
            tenant: tenant.to_string(),
            expected: canonical
                .iter()
                .map(|row| (row.seq, row_bytes(row)))
                .collect(),
            present: Arc::new(Mutex::new(initial.into_iter().collect())),
        };
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(sink.clone())
            .mount(&server)
            .await;
        let mut restarted = AuditChain::with_pg_pool(0, None, None, Some(pool.clone())).unwrap();
        restarted.clickhouse_client = Some(
            clickhouse::Client::default()
                .with_url(server.uri())
                .with_compression(clickhouse::Compression::None),
        );
        restarted.warm_from_postgres().await.unwrap();
        assert_eq!(
            *sink.present.lock(),
            BTreeSet::from([0, 1, 2]),
            "boot must recover absent rows, including holes below max(seq)"
        );
        assert_eq!(restarted.in_memory_seq(tenant), 3);
        // A second boot has nothing left to copy. Request count pins idempotency
        // independently of the sink's replacement semantics.
        let first_inserts = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.method == "POST")
            .count();
        assert!(first_inserts > 0, "copy recovery must execute an INSERT");
        restarted.warm_from_postgres().await.unwrap();
        assert_eq!(
            server
                .received_requests()
                .await
                .unwrap()
                .into_iter()
                .filter(|r| r.method == "POST")
                .count(),
            first_inserts
        );
    }
}

#[tokio::test]
async fn copy_head_restarts_at_genesis_for_holes() {
    let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
    for (count, high, expected) in [
        (0u64, 0u64, None),
        (1, 0, Some(0)),
        (3, 2, Some(2)),
        (2, 2, None),
        (1, u64::MAX, None),
    ] {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(
                wiremock::ResponseTemplate::new(200).set_body_bytes(
                    [count, high]
                        .into_iter()
                        .flat_map(u64::to_le_bytes)
                        .collect::<Vec<_>>(),
                ),
            )
            .expect(2)
            .mount(&server)
            .await;
        let client = clickhouse::Client::default()
            .with_url(server.uri())
            .with_compression(clickhouse::Compression::None);
        assert_eq!(
            read_ch_max_seq(&client, &tenant, true).await.unwrap(),
            expected
        );
        assert_eq!(
            read_ch_max_seq(&client, &tenant, false).await.unwrap(),
            (count > 0).then_some(high)
        );
    }
}

#[tokio::test]
async fn anchor_head_distinguishes_empty_from_sequence_zero() {
    let tenant = TenantId::from_jwt_claim(uuid::Uuid::new_v4());
    for (high, present, expected) in [(0u64, 0u8, None), (0, 1, Some(0)), (7, 1, Some(7))] {
        let server = wiremock::MockServer::start().await;
        let mut bytes = high.to_le_bytes().to_vec();
        bytes.push(present);
        wiremock::Mock::given(wiremock::matchers::any())
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(bytes))
            .expect(1)
            .mount(&server)
            .await;
        let client = clickhouse::Client::default()
            .with_url(server.uri())
            .with_compression(clickhouse::Compression::None);
        assert_eq!(
            read_last_anchored_end(&client, &tenant).await.unwrap(),
            expected
        );
    }
}

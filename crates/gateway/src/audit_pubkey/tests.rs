use super::*;
use axum::{body::Body, extract::ConnectInfo, http::Request};
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};
use tower::ServiceExt as _;

const MISSING: &str = "00000000-0000-4000-8000-000000000001";
const PRESENT: &str = "00000000-0000-4000-8000-000000000002";

#[derive(Default)]
struct Fake {
    calls: AtomicUsize,
    error: std::sync::atomic::AtomicBool,
    enrolled: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl PubkeyStore for Fake {
    async fn lookup(&self, tenant: uuid::Uuid) -> Result<Option<StoredKey>, StatusCode> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.error.load(Ordering::SeqCst) {
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
        Ok(
            (tenant.to_string() == PRESENT || self.enrolled.load(Ordering::SeqCst))
                .then(|| (B64.encode([7u8; 32]), String::new(), Some(42))),
        )
    }
}

fn fixture() -> (PubkeyState, Arc<Fake>) {
    let fake = Arc::new(Fake::default());
    let mut state = PubkeyState::new().with_platform_pubkey(Some(B64.encode([7u8; 32])));
    state.store = fake.clone();
    (state, fake)
}

fn request(id: &str, peer: &str) -> Request<Body> {
    Request::builder()
        .uri(format!("/v1/audit/pubkey?tenant_id={id}"))
        .extension(ConnectInfo(peer.parse::<SocketAddr>().unwrap()))
        .body(Body::empty())
        .unwrap()
}

async fn status(state: &PubkeyState, id: &str, peer: &str) -> StatusCode {
    routes()
        .with_state(state.clone())
        .oneshot(request(id, peer))
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn source_a_does_not_block_b() {
    let (state, _) = fixture();
    for _ in 0..601 {
        let _ = status(&state, MISSING, "198.51.100.1:1").await;
    }
    assert_eq!(
        status(&state, PRESENT, "198.51.100.2:1").await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn repeated_missing_uuid_reads_once() {
    let (state, fake) = fixture();
    for _ in 0..3 {
        assert_eq!(
            status(&state, MISSING, "198.51.100.1:1").await,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        fake.calls.load(Ordering::SeqCst),
        1,
        "confirmed misses must reuse the negative cache"
    );
}

#[tokio::test]
async fn concurrent_source_burst_is_bounded() {
    let (state, fake) = fixture();
    let barrier = Arc::new(tokio::sync::Barrier::new(81));
    let mut tasks = Vec::new();
    for i in 0..80 {
        let state = state.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            status(
                &state,
                &uuid::Uuid::from_u128(i).to_string(),
                "198.51.100.1:1",
            )
            .await
        }));
    }
    barrier.wait().await;
    for task in tasks {
        task.await.unwrap();
    }
    assert!(
        fake.calls.load(Ordering::SeqCst) <= 60,
        "one source exceeded its burst: {} reads",
        fake.calls.load(Ordering::SeqCst)
    );
}

#[tokio::test]
async fn db_error_not_cached() {
    let (state, fake) = fixture();
    fake.error.store(true, Ordering::SeqCst);
    assert_eq!(
        status(&state, PRESENT, "198.51.100.1:1").await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    fake.error.store(false, Ordering::SeqCst);
    assert_eq!(
        status(&state, PRESENT, "198.51.100.1:1").await,
        StatusCode::OK
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn existing_key_response() {
    let (state, _) = fixture();
    let response = routes()
        .with_state(state)
        .oneshot(request(PRESENT, "198.51.100.1:1"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let key = B64.encode([7u8; 32]);
    assert_eq!(value["ed25519_pubkey_b64"], key);
    assert_eq!(
        value["ed25519_fingerprint_sha256"],
        fingerprint_of_b64(&key)
    );
    assert_eq!(value["workspace_key_since_seq"], 42);
    assert_eq!(value["tenant_id"], PRESENT);
}

#[tokio::test]
async fn malformed_uuid_never_reads() {
    let (state, fake) = fixture();
    assert_eq!(
        status(&state, "not-a-uuid", "198.51.100.1:1").await,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    assert_eq!(state.abuse.as_ref().unwrap().sizes(), (0, 0, 0));
}

#[tokio::test]
async fn invalid_uuid_churn_cannot_occupy_sources() {
    let (state, fake) = fixture();
    let cap = state.abuse.as_ref().unwrap().policy.max_sources;
    for i in 0..=cap {
        let peer = format!("198.18.{}.{}:1", i / 256, i % 256);
        assert_eq!(
            status(&state, "invalid", &peer).await,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(state.abuse.as_ref().unwrap().sizes(), (0, 0, 0));
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        status(&state, PRESENT, "203.0.113.1:1").await,
        StatusCode::OK
    );
}

async fn forwarded(state: &PubkeyState, peer: Option<&str>, ip: &str) -> StatusCode {
    let mut req = request(PRESENT, peer.unwrap_or("198.51.100.1:1"));
    if peer.is_none() {
        req.extensions_mut().remove::<ConnectInfo<SocketAddr>>();
    }
    req.headers_mut()
        .insert("cf-connecting-ip", ip.parse().unwrap());
    req.headers_mut()
        .insert("x-forwarded-for", ip.parse().unwrap());
    routes()
        .with_state(state.clone())
        .oneshot(req)
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn trusted_proxy_isolates_clients() {
    let (state, _) = fixture();
    for _ in 0..601 {
        let _ = forwarded(&state, Some("127.0.0.1:443"), "198.51.100.1").await;
    }
    assert_eq!(
        forwarded(&state, Some("127.0.0.1:443"), "198.51.100.2").await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn untrusted_headers_do_not_mint_sources() {
    let (state, _) = fixture();
    for i in 1..=60 {
        assert_eq!(
            forwarded(&state, Some("198.51.100.1:1"), &format!("203.0.113.{i}")).await,
            StatusCode::OK
        );
    }
    assert_eq!(
        forwarded(&state, Some("198.51.100.1:1"), "203.0.113.99").await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn missing_peer_ignores_headers() {
    let (state, _) = fixture();
    for i in 1..=60 {
        let _ = forwarded(&state, None, &format!("203.0.113.{i}")).await;
    }
    assert_eq!(
        forwarded(&state, None, "203.0.113.99").await,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn ipv6_churn_is_bounded() {
    let (state, _) = fixture();
    for i in 0..60 {
        assert_eq!(
            status(&state, PRESENT, &format!("[2001:db8:1:{i:x}::1]:1")).await,
            StatusCode::OK
        );
    }
    assert_eq!(
        status(&state, PRESENT, "[2001:db8:1:ffff::1]:1").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        status(&state, PRESENT, "[2001:db8:2::1]:1").await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn platform_and_openapi_are_independent() {
    let (state, _) = fixture();
    for i in 0..601 {
        let _ = status(
            &state,
            &uuid::Uuid::from_u128(i).to_string(),
            "198.51.100.1:1",
        )
        .await;
    }
    for path in ["/v1/audit/platform-pubkey", "/v1/openapi.json"] {
        let req = Request::builder().uri(path).body(Body::empty()).unwrap();
        assert_eq!(
            routes()
                .with_state(state.clone())
                .oneshot(req)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
}

use std::time::{Duration, Instant};

fn with_policy(policy: abuse::Policy) -> (PubkeyState, Arc<Fake>) {
    let (mut state, fake) = fixture();
    state.abuse = Some(Arc::new(abuse::Abuse::new(policy)));
    (state, fake)
}

fn clock(state: &mut PubkeyState) -> Arc<parking_lot::Mutex<Instant>> {
    let clock = Arc::new(parking_lot::Mutex::new(Instant::now()));
    let read = clock.clone();
    Arc::get_mut(state.abuse.as_mut().unwrap()).unwrap().clock = Arc::new(move || *read.lock());
    clock
}

#[tokio::test]
async fn enrollment_visible_at_ttl() {
    let (mut state, fake) = fixture();
    let clock = clock(&mut state);
    assert_eq!(
        status(&state, MISSING, "198.51.100.1:1").await,
        StatusCode::NOT_FOUND
    );
    fake.enrolled.store(true, Ordering::SeqCst);
    assert_eq!(
        status(&state, MISSING, "198.51.100.1:1").await,
        StatusCode::NOT_FOUND
    );
    *clock.lock() += Duration::from_secs(5);
    assert_eq!(
        status(&state, MISSING, "198.51.100.1:1").await,
        StatusCode::OK
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn miss_hits_do_not_extend_ttl() {
    let (mut state, fake) = fixture();
    let clock = clock(&mut state);
    assert_eq!(
        status(&state, MISSING, "198.51.100.1:1").await,
        StatusCode::NOT_FOUND
    );
    for _ in 0..4 {
        *clock.lock() += Duration::from_secs(1);
        assert_eq!(
            status(&state, MISSING, "198.51.100.1:1").await,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    *clock.lock() += Duration::from_secs(1);
    assert_eq!(
        status(&state, MISSING, "198.51.100.1:1").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn distinct_misses_are_bounded() {
    let mut policy = abuse::Policy::shipped().unwrap();
    policy.negative_max_entries = 4;
    let (state, fake) = with_policy(policy);
    for i in 10..42 {
        assert_eq!(
            status(
                &state,
                &uuid::Uuid::from_u128(i).to_string(),
                "198.51.100.1:1"
            )
            .await,
            StatusCode::NOT_FOUND
        );
        let (_, misses, index) = state.abuse.as_ref().unwrap().sizes();
        assert!(misses <= 4);
        assert_eq!(index, misses, "expiry metadata must be bounded too");
    }
    let before = fake.calls.load(Ordering::SeqCst);
    assert_eq!(
        status(
            &state,
            &uuid::Uuid::from_u128(10).to_string(),
            "198.51.100.1:1"
        )
        .await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        fake.calls.load(Ordering::SeqCst),
        before + 1,
        "oldest miss was evicted"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_source_churn_is_bounded() {
    let mut policy = abuse::Policy::shipped().unwrap();
    policy.max_sources = 8;
    let (state, _) = with_policy(policy);
    let barrier = Arc::new(tokio::sync::Barrier::new(129));
    let mut tasks = Vec::new();
    for i in 0..128 {
        let state = state.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let _ = status(&state, MISSING, &format!("[2001:db8:{i:x}::1]:1")).await;
            assert!(state.abuse.as_ref().unwrap().sizes().0 <= 8);
        }));
    }
    barrier.wait().await;
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(state.abuse.as_ref().unwrap().sizes().0, 8);
}

#[tokio::test]
async fn saturated_sources_admit_new_source_with_bounded_memory() {
    let mut policy = abuse::Policy::shipped().unwrap();
    policy.max_sources = 8;
    let burst = policy.source_per_minute;
    let (state, fake) = with_policy(policy);
    // All slots remain occupied by valid requests, including cache hits that
    // cost no DB work. Exhaust each attacker's own allowance first.
    for i in 1..=8 {
        for _ in 0..burst {
            assert_eq!(
                status(&state, MISSING, &format!("198.51.100.{i}:1")).await,
                StatusCode::NOT_FOUND
            );
        }
    }
    for _ in 0..3 {
        for i in 1..=8 {
            assert_eq!(
                status(&state, MISSING, &format!("198.51.100.{i}:1")).await,
                StatusCode::TOO_MANY_REQUESTS
            );
        }
        let mut admitted = false;
        for _ in 0..2 {
            if status(&state, PRESENT, "203.0.113.1:1").await == StatusCode::OK {
                admitted = true;
                break;
            }
        }
        assert!(
            admitted,
            "a full source map must not permanently refuse a new source"
        );
        assert_eq!(state.abuse.as_ref().unwrap().sizes().0, 8);
    }
    assert_eq!(fake.calls.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn throttled_sources_do_not_refresh_idle_recency() {
    let mut policy = abuse::Policy::shipped().unwrap();
    policy.max_sources = 2;
    policy.source_per_minute = 1;
    let (mut state, _) = with_policy(policy);
    let clock = clock(&mut state);
    for i in 1..=2 {
        assert_eq!(
            status(&state, PRESENT, &format!("198.51.100.{i}:1")).await,
            StatusCode::OK
        );
    }
    *clock.lock() += Duration::from_secs(59);
    for i in 1..=2 {
        assert_eq!(
            status(&state, PRESENT, &format!("198.51.100.{i}:1")).await,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    *clock.lock() += Duration::from_secs(1);
    assert_eq!(
        status(&state, PRESENT, "203.0.113.1:1").await,
        StatusCode::OK
    );
    assert_eq!(state.abuse.as_ref().unwrap().sizes().0, 1);
}

#[tokio::test]
async fn overflow_is_shared_bounded_and_cannot_gain_a_fresh_burst() {
    let mut policy = abuse::Policy::shipped().unwrap();
    policy.max_sources = 1;
    let (mut state, fake) = with_policy(policy);
    let clock = clock(&mut state);
    assert_eq!(
        status(&state, MISSING, "198.51.100.1:1").await,
        StatusCode::NOT_FOUND
    );
    *clock.lock() += Duration::from_secs(1);
    // One overflow client spends the small shared burst.
    for _ in 0..6 {
        assert_eq!(
            status(&state, PRESENT, "203.0.113.1:1").await,
            StatusCode::OK
        );
    }
    for i in 1..=16 {
        let response = routes()
            .with_state(state.clone())
            .oneshot(request(PRESENT, &format!("203.0.113.{i}:1")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(
            response.headers()["retry-after"]
                .to_str()
                .unwrap()
                .parse::<u32>()
                .unwrap()
                >= 1
        );
        assert_eq!(state.abuse.as_ref().unwrap().sizes().0, 1);
    }
    // The tracked source is now idle, but the overflow client has not had a
    // full refill interval. Promotion must not reset that client's allowance.
    *clock.lock() += Duration::from_secs(59);
    assert_eq!(
        status(&state, PRESENT, "203.0.113.1:1").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 7);
    *clock.lock() += Duration::from_secs(1);
    assert_eq!(
        status(&state, PRESENT, "203.0.113.1:1").await,
        StatusCode::OK
    );
    assert_eq!(state.abuse.as_ref().unwrap().sizes().0, 1);
}

#[tokio::test]
async fn global_store_budget_is_bounded() {
    let mut policy = abuse::Policy::shipped().unwrap();
    policy.store_per_minute = 1;
    let (state, fake) = with_policy(policy);
    assert_eq!(
        status(&state, MISSING, "198.51.100.1:1").await,
        StatusCode::NOT_FOUND
    );
    // A cached miss and the in-memory routes are independent of store exhaustion.
    assert_eq!(
        status(&state, MISSING, "198.51.100.2:1").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status(&state, PRESENT, "198.51.100.3:1").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
    for path in ["/v1/audit/platform-pubkey", "/v1/openapi.json"] {
        let req = Request::builder().uri(path).body(Body::empty()).unwrap();
        assert_eq!(
            routes()
                .with_state(state.clone())
                .oneshot(req)
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
    }
}

struct BlockingStore {
    entered: tokio::sync::mpsc::UnboundedSender<()>,
    release: tokio::sync::Semaphore,
}

#[async_trait::async_trait]
impl PubkeyStore for BlockingStore {
    async fn lookup(&self, _: uuid::Uuid) -> Result<Option<StoredKey>, StatusCode> {
        self.entered.send(()).unwrap();
        self.release.acquire().await.unwrap().forget();
        Ok(None)
    }
}

fn blocking(
    state: &mut PubkeyState,
) -> (Arc<BlockingStore>, tokio::sync::mpsc::UnboundedReceiver<()>) {
    let (entered, rx) = tokio::sync::mpsc::unbounded_channel();
    let store = Arc::new(BlockingStore {
        entered,
        release: tokio::sync::Semaphore::new(0),
    });
    state.store = store.clone();
    (store, rx)
}

#[tokio::test]
async fn concurrent_store_work_is_bounded() {
    let (mut state, _) = fixture();
    let (store, mut entered) = blocking(&mut state);
    let mut tasks = Vec::new();
    for i in 1..=4 {
        let s = state.clone();
        tasks.push(tokio::spawn(async move {
            status(&s, MISSING, &format!("198.51.100.{i}:1")).await
        }));
        entered.recv().await.unwrap(); // actual lookup holds the permit; no sleeps
    }
    assert_eq!(
        status(&state, PRESENT, "198.51.100.9:1").await,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert!(
        entered.try_recv().is_err(),
        "fifth request never reached store"
    );
    store.release.add_permits(4);
    for task in tasks {
        assert_eq!(task.await.unwrap(), StatusCode::NOT_FOUND);
    }
    assert_eq!(state.abuse.as_ref().unwrap().slots.available_permits(), 4);
    assert_eq!(
        state.abuse.as_ref().unwrap().sizes().1,
        1,
        "overlapping misses don't duplicate cache entries"
    );
}

#[tokio::test]
async fn cancellation_releases_slot() {
    let mut policy = abuse::Policy::shipped().unwrap();
    policy.store_concurrency = 1;
    let (mut state, fake) = with_policy(policy);
    let (_, mut entered) = blocking(&mut state);
    let s = state.clone();
    let task = tokio::spawn(async move { status(&s, MISSING, "198.51.100.1:1").await });
    entered.recv().await.unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(state.abuse.as_ref().unwrap().sizes().1, 0);
    state.store = fake.clone();
    assert_eq!(
        status(&state, MISSING, "198.51.100.2:1").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn timeout_not_cached() {
    let mut policy = abuse::Policy::shipped().unwrap();
    policy.lookup_timeout_ms = 1;
    let (mut state, fake) = with_policy(policy);
    let (_, _entered) = blocking(&mut state);
    assert_eq!(
        status(&state, MISSING, "198.51.100.1:1").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(state.abuse.as_ref().unwrap().sizes().1, 0);
    state.store = fake.clone();
    assert_eq!(
        status(&state, MISSING, "198.51.100.1:1").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn delayed_miss_cannot_extend_enrollment_visibility() {
    let (mut state, fake) = fixture();
    let clock = clock(&mut state);
    let (store, mut entered) = blocking(&mut state);
    let s = state.clone();
    let task = tokio::spawn(async move { status(&s, MISSING, "198.51.100.1:1").await });
    entered.recv().await.unwrap();
    *clock.lock() += Duration::from_secs(5);
    fake.enrolled.store(true, Ordering::SeqCst);
    store.release.add_permits(1);
    assert_eq!(task.await.unwrap(), StatusCode::NOT_FOUND);
    assert_eq!(state.abuse.as_ref().unwrap().sizes().1, 0);
    state.store = fake;
    assert_eq!(
        status(&state, MISSING, "198.51.100.1:1").await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn workspace_response_is_not_http_cached() {
    let (state, _) = fixture();
    for id in [MISSING, PRESENT, "invalid"] {
        let response = routes()
            .with_state(state.clone())
            .oneshot(request(id, "198.51.100.1:1"))
            .await
            .unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
    }
}

#[test]
fn shipped_policy_and_invalid_bounds() {
    let raw = include_str!("../../translation_policy.v1.json");
    let p = abuse::Policy::parse(raw).unwrap();
    assert_eq!(p.negative_ttl_secs, 5);
    assert_eq!(p.source_per_minute, 60);
    assert_eq!(p.store_per_minute, 600);
    let original: serde_json::Value = serde_json::from_str(raw).unwrap();
    for key in [
        "source_per_minute",
        "max_sources",
        "source_idle_secs",
        "store_per_minute",
        "store_concurrency",
        "lookup_timeout_ms",
        "negative_max_entries",
        "negative_ttl_secs",
    ] {
        let mut value = original.clone();
        value["audit_pubkey"][key] = 0.into();
        assert!(abuse::Policy::parse(&value.to_string()).is_none(), "{key}");
    }
    assert!(abuse::Policy::parse("{}").is_none());
    assert!(abuse::Policy::parse("garbage").is_none());
}

#[tokio::test]
async fn invalid_policy_fails_closed() {
    let (mut state, fake) = fixture();
    state.abuse = None;
    assert_eq!(
        status(&state, PRESENT, "198.51.100.1:1").await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
}

/// Real SQL against a disposable postgres:17-alpine only. Set B581_POSTGRES_PORT;
/// credentials/database are fixture-only, host is fixed loopback. No global pool.
#[tokio::test]
#[ignore = "requires disposable local Postgres; see B581_POSTGRES_PORT"]
async fn postgres_pubkey_cache_lifecycle() {
    let mut config = deadpool_postgres::Config::new();
    config.host = Some("127.0.0.1".into());
    config.port = Some(
        std::env::var("B581_POSTGRES_PORT")
            .expect("local fixture port")
            .parse()
            .unwrap(),
    );
    config.user = Some("b581".into());
    config.password = Some("unit-test-b581".into());
    config.dbname = Some("b581".into());
    let pool = config
        .create_pool(
            Some(deadpool_postgres::Runtime::Tokio1),
            tokio_postgres::NoTls,
        )
        .unwrap();
    let client = pool.get().await.unwrap();
    for migration in [
        include_str!("../../../../apps/web/db/migrations/0000_initial_baseline.sql"),
        include_str!("../../../../apps/web/db/migrations/0001_reconcile_gateway_tables.sql"),
        include_str!("../../../../apps/web/db/migrations/0014_rekor_v2_anchor_key.sql"),
        include_str!("../../../../apps/web/db/migrations/0047_adr078_ledger_canonical_pg.sql"),
    ] {
        client.batch_execute(migration).await.unwrap();
    }
    let (mut state, _) = fixture();
    let clock = clock(&mut state);
    state.store = Arc::new(PostgresStore(Some(pool.clone())));
    assert_eq!(
        status(&state, MISSING, "198.51.100.1:1").await,
        StatusCode::NOT_FOUND
    );
    // If the second missing request ran SQL, renaming its table would yield 500.
    client
        .batch_execute("ALTER TABLE tenant_audit_keys RENAME TO hidden_keys")
        .await
        .unwrap();
    assert_eq!(
        status(&state, MISSING, "198.51.100.1:1").await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        status(&state, PRESENT, "198.51.100.1:1").await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    client
        .batch_execute("ALTER TABLE hidden_keys RENAME TO tenant_audit_keys")
        .await
        .unwrap();
    let key = B64.encode([7u8; 32]);
    let anchor = B64.encode(b"fixture-spki-bytes");
    for id in [MISSING, PRESENT] {
        let tenant = uuid::Uuid::parse_str(id).unwrap();
        client
            .execute(
                "INSERT INTO tenants (id, workos_org_id) VALUES ($1, $2)",
                &[&tenant, &format!("fixture-{id}")],
            )
            .await
            .unwrap();
        client.execute("INSERT INTO tenant_audit_keys (tenant_id, encrypted_private_key, public_key_b64, anchor_pubkey_spki_b64) VALUES ($1, 'fixture-only-not-a-private-key', $2, $3)", &[&tenant, &key, &anchor]).await.unwrap();
        client.execute("INSERT INTO audit_anchor_records (tenant_id, batch_start_seq, batch_end_seq, merkle_root, anchor_state, ed25519_pubkey, anchored_at) VALUES ($1, 42, 43, 'fixture-root', 'pending', $2, now())", &[&tenant, &key]).await.unwrap();
    }
    // The failed read of PRESENT was not negative-cached; the confirmed miss was.
    assert_eq!(
        status(&state, PRESENT, "198.51.100.1:1").await,
        StatusCode::OK
    );
    assert_eq!(
        status(&state, MISSING, "198.51.100.1:1").await,
        StatusCode::NOT_FOUND
    );
    *clock.lock() += Duration::from_secs(5);
    let response = routes()
        .with_state(state.clone())
        .oneshot(request(MISSING, "198.51.100.1:1"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["tenant_id"], MISSING);
    assert_eq!(value["ed25519_pubkey_b64"], key);
    assert_eq!(
        value["ed25519_fingerprint_sha256"],
        fingerprint_of_b64(&key)
    );
    assert_eq!(value["anchor_ecdsa_spki_b64"], anchor);
    assert_eq!(
        value["anchor_ecdsa_fingerprint_sha256"],
        fingerprint_of_b64(&anchor)
    );
    assert_eq!(value["workspace_key_since_seq"], 42);
    client
        .batch_execute("ALTER TABLE audit_anchor_records RENAME TO hidden_anchors")
        .await
        .unwrap();
    assert_eq!(
        status(&state, PRESENT, "198.51.100.1:1").await,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    client
        .batch_execute("ALTER TABLE hidden_anchors RENAME TO audit_anchor_records")
        .await
        .unwrap();
    assert_eq!(
        status(&state, PRESENT, "198.51.100.1:1").await,
        StatusCode::OK
    );
    let absent = uuid::Uuid::new_v4().to_string();
    assert_eq!(
        status(&state, &absent, "198.51.100.1:1").await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_distinct_misses_are_bounded() {
    let mut policy = abuse::Policy::shipped().unwrap();
    policy.negative_max_entries = 4;
    let (state, _) = with_policy(policy);
    let barrier = Arc::new(tokio::sync::Barrier::new(129));
    let mut tasks = Vec::new();
    for i in 10..138 {
        let state = state.clone();
        let barrier = barrier.clone();
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            let result = status(
                &state,
                &uuid::Uuid::from_u128(i).to_string(),
                &format!("198.51.100.{i}:1"),
            )
            .await;
            assert!(matches!(
                result,
                StatusCode::NOT_FOUND | StatusCode::TOO_MANY_REQUESTS
            ));
            let (_, entries, expiry) = state.abuse.as_ref().unwrap().sizes();
            assert!(entries <= 4);
            assert_eq!(entries, expiry);
        }));
    }
    barrier.wait().await;
    for task in tasks {
        task.await.unwrap();
    }
    assert_eq!(state.abuse.as_ref().unwrap().sizes().1, 4);
}

#[tokio::test]
async fn uuid_spellings_share_one_miss() {
    let (state, fake) = fixture();
    for id in [
        "abcdefab-cdef-4abc-8def-abcdefabcdef",
        "ABCDEFAB-CDEF-4ABC-8DEF-ABCDEFABCDEF",
    ] {
        assert_eq!(
            status(&state, id, "198.51.100.1:1").await,
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(fake.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn throttled_response_has_retry_after() {
    let mut policy = abuse::Policy::shipped().unwrap();
    policy.source_per_minute = 1;
    let (state, _) = with_policy(policy);
    assert_eq!(
        status(&state, PRESENT, "198.51.100.1:1").await,
        StatusCode::OK
    );
    let response = routes()
        .with_state(state)
        .oneshot(request(PRESENT, "198.51.100.1:1"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert!(
        response.headers()["retry-after"]
            .to_str()
            .unwrap()
            .parse::<u32>()
            .unwrap()
            >= 1
    );
    assert_eq!(response.headers()["cache-control"], "no-store");
}

//! ACT-15 agent authority register, against a real migrated Postgres. All values synthetic.
use super::policy_pg_tests::setup;
use super::policy_store::activate_tx;
use super::tests::{claims, fixture, grants};
use super::*;
use axum::http::StatusCode;
use tower::ServiceExt;

const PHC: &str = "synthetic-phc-marker-0001";
const KEYHASH: &str = "synthetic-keyhash-marker-0002";

/// Entitlement source: flag on, flag off, no cache at all (no control plane), resolver outage.
#[derive(Clone, Copy, PartialEq)]
enum M {
    On,
    Off,
    NoCache,
    Outage,
}
fn state(pool: &deadpool_postgres::Pool, mode: M) -> crate::server::AppState {
    let mut s =
        crate::handler_harness::test_state(crate::providers::ProviderRegistry::new().unwrap());
    s.pg = Some(pool.clone());
    let mut e = grants();
    e.action_control = mode == M::On;
    s.entitlements = (mode != M::NoCache).then(|| {
        std::sync::Arc::new(crate::entitlement_cache::EntitlementCache::new(
            std::sync::Arc::new(move |_| {
                let r = e.clone();
                Box::pin(async move {
                    if mode == M::Outage {
                        Err(anyhow::anyhow!("synthetic outage"))
                    } else {
                        Ok(r)
                    }
                })
            }),
        ))
    });
    s
}
async fn get_as(
    pool: &deadpool_postgres::Pool,
    auth: &crate::auth::Claims,
    mode: M,
    uri: &str,
) -> (StatusCode, Value) {
    let _a = crate::auth::test_claims::Guard::set(auth.clone());
    let _o =
        crate::control_plane::test_overrides::Guard::new(Some(Ok(Default::default())), None, None);
    let r = crate::mcp_routes::router(state(pool, mode))
        .oneshot(
            axum::http::Request::builder()
                .uri(uri)
                .header("authorization", "Bearer synthetic")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = r.status();
    let bytes = axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}
async fn reg(pool: &deadpool_postgres::Pool, auth: &crate::auth::Claims) -> Value {
    let (s, b) = get_as(pool, auth, M::On, "/v1/action-authority").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    b
}
async fn publish(pool: &deadpool_postgres::Pool, auth: &crate::auth::Claims, c: &str, p: &str) {
    let mut client = pool.get().await.unwrap();
    let tx = client.transaction().await.unwrap();
    activate_tx(&tx, auth, Some(&grants()), c, p).await.unwrap();
    tx.commit().await.unwrap();
}
/// Insert a synthetic key; `revoked` is a SQL interval offset from now (negative = past).
async fn key(
    pool: &deadpool_postgres::Pool,
    t: &TenantId,
    name: &str,
    revoked: Option<&str>,
) -> Uuid {
    let id = Uuid::new_v4();
    let c = pool.get().await.unwrap();
    c.execute(
        "INSERT INTO api_keys(id,tenant_id,name,key_prefix,minted_by,lookup_hash,argon2id_phc,key_hash,revoked_at) \
         VALUES($1,$2,$3,'tl_syn',$4,decode(md5($3),'hex'),$5,$6||$3, CASE WHEN $7::text IS NULL THEN NULL ELSE now()+$7::text::interval END)",
        &[&id, t.as_uuid(), &name, &"synthetic-minter", &PHC, &KEYHASH, &revoked],
    )
    .await
    .unwrap();
    id
}
fn with(p: &str, f: impl FnOnce(&mut Value)) -> String {
    let mut v: Value = serde_json::from_str(p).unwrap();
    f(&mut v);
    v.to_string()
}
fn tools(b: &Value) -> &Vec<Value> {
    b["protected_tools"].as_array().unwrap()
}
fn agent(b: &Value, id: Uuid) -> &Value {
    b["agents"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["key_id"] == id.to_string())
        .unwrap()
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_lists_protected_tools() {
    let (pool, auth, c, p) = setup().await;
    publish(&pool, &auth, &c, &p).await;
    let b = reg(&pool, &auth).await;
    let t = &tools(&b)[0];
    let hash: String = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT policy_hash FROM action_policies WHERE tenant_id=$1",
            &[auth.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(tools(&b).len(), 1);
    assert_eq!(t["tool_name"], "pay");
    assert_eq!(t["server_slug"], "synthetic");
    assert_eq!(t["policy_version"], 1);
    assert_eq!(t["policy_hash"], hash);
    assert_eq!(t["publisher_sub"], "synthetic-publisher");
    assert_eq!(t["default"], "deny");
    assert_eq!(b["workspace"]["action_control"], true);
    assert_eq!(b["workspace"]["tenant_id"], auth.tenant_id.to_string());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_summarises_rules() {
    let (pool, auth, c, p) = setup().await;
    let p = with(
        &p,
        |v| v["rules"] = json!([{"id":"small","when":[],"decision":"allow"},{"id":"rest","when":[],"decision":"deny"}]),
    );
    publish(&pool, &auth, &c, &p).await;
    let b = reg(&pool, &auth).await;
    assert_eq!(
        tools(&b)[0]["rules"],
        json!([{"id":"small","decision":"allow"},{"id":"rest","decision":"deny"}])
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_agents_all_permits_every_key() {
    let (pool, auth, c, p) = setup().await;
    publish(&pool, &auth, &c, &p).await;
    let (k1, k2) = (
        key(&pool, &auth.tenant_id, "a", None).await,
        key(&pool, &auth.tenant_id, "b", None).await,
    );
    let b = reg(&pool, &auth).await;
    let tool_ref = tools(&b)[0]["tool_ref"].clone();
    assert_eq!(tools(&b)[0]["agents"], "all");
    for k in [k1, k2] {
        assert_eq!(
            agent(&b, k)["protected_tools_in_policy_scope"],
            json!([tool_ref])
        );
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_agents_list_limits_permission() {
    let (pool, auth, c, p) = setup().await;
    let (k1, k2) = (
        key(&pool, &auth.tenant_id, "a", None).await,
        key(&pool, &auth.tenant_id, "b", None).await,
    );
    publish(&pool, &auth, &c, &with(&p, |v| v["agents"] = json!([k1]))).await;
    let b = reg(&pool, &auth).await;
    assert_eq!(tools(&b)[0]["agents"], json!([k1]));
    assert_eq!(
        agent(&b, k1)["protected_tools_in_policy_scope"],
        json!([tools(&b)[0]["tool_ref"]])
    );
    assert_eq!(agent(&b, k2)["protected_tools_in_policy_scope"], json!([]));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_lists_observed_only_servers() {
    let (pool, auth, c, p) = setup().await;
    publish(&pool, &auth, &c, &p).await;
    let other = Uuid::new_v4();
    pool.get().await.unwrap().execute("INSERT INTO mcp_servers(id,tenant_id,slug,name,url,transport,auth_mode) VALUES ($1,$2,'observed','Observed','https://example.invalid','streamable_http','none')", &[&other, auth.tenant_id.as_uuid()]).await.unwrap();
    let b = reg(&pool, &auth).await;
    assert_eq!(
        b["observed_only_servers"],
        json!([{"server_id":other,"server_slug":"observed"}])
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_key_metadata_matches_row() {
    let (pool, auth, _, _) = setup().await;
    let k = key(&pool, &auth.tenant_id, "payments-bot", None).await;
    pool.get().await.unwrap().execute("UPDATE api_keys SET scope=ARRAY['chat'], expires_at=now()+interval '30 days', budget_usd_monthly=12.5, rate_limit_rpm=77 WHERE id=$1", &[&k]).await.unwrap();
    let b = reg(&pool, &auth).await;
    let a = agent(&b, k);
    assert_eq!(a["name"], "payments-bot");
    assert_eq!(a["key_prefix"], "tl_syn");
    assert_eq!(a["minted_by"], "synthetic-minter");
    assert_eq!(a["scope"], json!(["chat"]));
    assert_eq!(a["budget_usd_monthly"], "12.5000");
    assert_eq!(a["rate_limit_rpm"], 77);
    assert!(
        a["expires_at"].is_string() && a["created_at"].is_string() && a["last_used_at"].is_null()
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_shows_pause_state() {
    let (pool, auth, c, p) = setup().await;
    publish(&pool, &auth, &c, &p).await;
    assert!(reg(&pool, &auth).await["workspace"]["paused_at"].is_null());
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE workspace_controls SET paused_at=now() WHERE tenant_id=$1",
            &[auth.tenant_id.as_uuid()],
        )
        .await
        .unwrap();
    assert!(reg(&pool, &auth).await["workspace"]["paused_at"].is_string());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_digest_is_deterministic() {
    let (pool, auth, c, p) = setup().await;
    publish(&pool, &auth, &c, &p).await;
    key(&pool, &auth.tenant_id, "a", None).await;
    let (x, y) = (reg(&pool, &auth).await, reg(&pool, &auth).await);
    assert_eq!(x["register_digest"], y["register_digest"]);
    let mut z = x.clone();
    for k in ["register_digest", "generated_at"] {
        z.as_object_mut().unwrap().remove(k);
    }
    for a in z["agents"].as_array_mut().unwrap() {
        a.as_object_mut().unwrap().remove("last_used_at");
    }
    assert_eq!(x["register_digest"], sha(canonical(&z).unwrap().as_bytes()));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_digest_changes_with_policy() {
    let (pool, auth, c, p) = setup().await;
    publish(&pool, &auth, &c, &p).await;
    let before = reg(&pool, &auth).await;
    publish(&pool, &auth, &c, &with(&p, |v| v["version"] = json!(2))).await;
    let after = reg(&pool, &auth).await;
    assert_eq!(tools(&after)[0]["policy_version"], 2);
    assert_ne!(before["register_digest"], after["register_digest"]);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_states_separation_rules() {
    let (pool, auth, _, _) = setup().await;
    assert_eq!(
        reg(&pool, &auth).await["approval"],
        json!({"capability":"approve_tool_calls","separation":["approver != key minter","approver != policy publisher"]})
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_flag_off_lists_agents_only() {
    let (pool, auth, c, p) = setup().await;
    publish(&pool, &auth, &c, &p).await;
    let k = key(&pool, &auth.tenant_id, "a", None).await;
    let (s, b) = get_as(&pool, &auth, M::Off, "/v1/action-authority").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["workspace"]["action_control"], false);
    assert_eq!(b["protected_tools"], json!([]));
    assert!(agent(&b, k)["protected_tools_in_policy_scope"].is_null());
    assert_eq!(b["unprotected_tools"], json!([]));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_never_exposes_key_material() {
    let (pool, auth, c, p) = setup().await;
    publish(&pool, &auth, &c, &p).await;
    let c = pool.get().await.unwrap();
    c.execute(
        "INSERT INTO api_keys(id,tenant_id,name,key_prefix,minted_by,lookup_hash,argon2id_phc,key_hash) \
         VALUES(gen_random_uuid(),$1,'fixed','tl_syn','synthetic-minter','\\xdeadbeefcafebabe'::bytea,$2,$3)",
        &[auth.tenant_id.as_uuid(), &PHC, &KEYHASH],
    )
    .await
    .unwrap();
    let body = reg(&pool, &auth).await.to_string();
    assert!(body.contains("\"fixed\""), "the seeded key must be listed");
    for needle in [
        PHC,
        KEYHASH,
        "deadbeefcafebabe",
        "3q2+78r+ur4=",
        "[222,173,190,239,202,254,186,190]",
        "lookup_hash",
        "argon2id_phc",
        "key_hash",
    ] {
        assert!(!body.contains(needle), "leaked {needle}");
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_excludes_revoked_keys() {
    let (pool, auth, _, _) = setup().await;
    let dead = key(&pool, &auth.tenant_id, "dead", Some("-1 hour")).await;
    let scheduled = key(&pool, &auth.tenant_id, "scheduled", Some("1 hour")).await;
    let b = reg(&pool, &auth).await;
    let ids: Vec<_> = b["agents"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["key_id"].clone())
        .collect();
    assert_eq!(ids, vec![json!(scheduled)]);
    assert!(!ids.contains(&json!(dead)));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_excludes_other_tenant_keys() {
    let (pool, auth, _, _) = setup().await;
    let other = TenantId::from_jwt_claim(Uuid::new_v4());
    crate::db::tenants::create(&pool, *other.as_uuid(), "synthetic-other", "free")
        .await
        .unwrap();
    key(&pool, &other, "theirs", None).await;
    let mine = key(&pool, &auth.tenant_id, "mine", None).await;
    let b = reg(&pool, &auth).await;
    assert_eq!(b["agents"].as_array().unwrap().len(), 1);
    assert_eq!(b["agents"][0]["key_id"], mine.to_string());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_excludes_other_tenant_policies() {
    let (pool, auth, c, p) = setup().await;
    let other = TenantId::from_jwt_claim(Uuid::new_v4());
    crate::db::tenants::create(&pool, *other.as_uuid(), "synthetic-other", "free")
        .await
        .unwrap();
    let server = Uuid::new_v4();
    let db = pool.get().await.unwrap();
    db.execute("INSERT INTO mcp_servers(id,tenant_id,slug,name,url,transport,auth_mode) VALUES ($1,$2,'theirs','Theirs','https://example.invalid','streamable_http','none')", &[&server, other.as_uuid()]).await.unwrap();
    let mut theirs = auth.clone();
    theirs.tenant_id = other.clone();
    let tc = with(&c, |v| {
        v["tool_ref"] = json!(Uuid::new_v4());
        v["server_id"] = json!(server);
        v["tool_name"] = json!("refund");
    });
    publish(
        &pool,
        &theirs,
        &tc,
        &with(&p, |v| v["policy_id"] = json!(Uuid::new_v4())),
    )
    .await;
    let b = reg(&pool, &auth).await;
    assert_eq!(tools(&b).len(), 0);
    assert_eq!(b["observed_only_servers"].as_array().unwrap().len(), 1);
    assert_eq!(
        reg(&pool, &theirs).await["protected_tools"][0]["tool_name"],
        "refund"
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_requires_view_policies() {
    let (pool, mut auth, _, _) = setup().await;
    auth.role = Some(crate::auth::Role::Member);
    let (s, _) = get_as(&pool, &auth, M::On, "/v1/action-authority").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_keeps_tool_of_archived_server() {
    let (pool, auth, c, p) = setup().await;
    publish(&pool, &auth, &c, &p).await;
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE mcp_servers SET archived_at=now() WHERE tenant_id=$1",
            &[auth.tenant_id.as_uuid()],
        )
        .await
        .unwrap();
    let b = reg(&pool, &auth).await;
    assert_eq!(tools(&b).len(), 1);
    assert!(tools(&b)[0]["server_slug"].is_null());
    assert_eq!(b["observed_only_servers"], json!([]));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_revoked_key_in_policy_not_listed_as_agent() {
    let (pool, auth, c, p) = setup().await;
    let dead = key(&pool, &auth.tenant_id, "dead", Some("-1 hour")).await;
    let live = key(&pool, &auth.tenant_id, "live", None).await;
    publish(
        &pool,
        &auth,
        &c,
        &with(&p, |v| v["agents"] = json!([dead, live])),
    )
    .await;
    let b = reg(&pool, &auth).await;
    assert_eq!(tools(&b)[0]["agents"], json!([dead, live]));
    assert_eq!(b["agents"].as_array().unwrap().len(), 1);
    assert_eq!(b["agents"][0]["key_id"], live.to_string());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_flags_truncated_agents() {
    let (pool, auth, _, _) = setup().await;
    let cap = crate::mcp_policy::settings()
        .unwrap()
        .approvals
        .max_list_page_size;
    let ins = "INSERT INTO api_keys(id,tenant_id,name,key_prefix,created_at) SELECT gen_random_uuid(),$1,'k'||g,'tl_syn',now()+g*interval '1 second' FROM generate_series(1,$2::int) g";
    let db = pool.get().await.unwrap();
    db.execute(ins, &[auth.tenant_id.as_uuid(), &(cap as i32)])
        .await
        .unwrap();
    let b = reg(&pool, &auth).await;
    assert_eq!(b["agents"].as_array().unwrap().len(), cap);
    assert_eq!(b["agents_truncated"], false);
    db.execute("INSERT INTO api_keys(id,tenant_id,name,key_prefix) VALUES (gen_random_uuid(),$1,'extra','tl_syn')", &[auth.tenant_id.as_uuid()]).await.unwrap();
    let b = reg(&pool, &auth).await;
    assert_eq!(b["agents"].as_array().unwrap().len(), cap);
    assert_eq!(b["agents_truncated"], true);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_ignores_query_tenant() {
    let (pool, auth, _, _) = setup().await;
    let other = TenantId::from_jwt_claim(Uuid::new_v4());
    crate::db::tenants::create(&pool, *other.as_uuid(), "synthetic-other", "free")
        .await
        .unwrap();
    key(&pool, &other, "theirs", None).await;
    let mine = key(&pool, &auth.tenant_id, "mine", None).await;
    let (s, b) = get_as(
        &pool,
        &auth,
        M::On,
        &format!("/v1/action-authority?tenant_id={other}"),
    )
    .await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["agents"].as_array().unwrap().len(), 1);
    assert_eq!(b["agents"][0]["key_id"], mine.to_string());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_db_failure_503() {
    let (pool, auth, _, _) = setup().await;
    pool.close();
    let (s, b) = get_as(&pool, &auth, M::On, "/v1/action-authority").await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(b["error"], "register_unavailable");
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_empty_tenant() {
    let (pool, tenant) = fixture().await;
    let mut auth = claims(&tenant);
    auth.auth_method = crate::auth::AuthMethod::JwtBearer;
    auth.role = Some(crate::auth::Role::Owner);
    let b = reg(&pool, &auth).await;
    for k in ["protected_tools", "observed_only_servers", "agents"] {
        assert_eq!(b[k], json!([]), "{k}");
    }
    assert_eq!(b["register_digest"].as_str().unwrap().len(), 64);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_lists_tool_downgraded_to_unprotected() {
    let (pool, auth, c, p) = setup().await;
    publish(&pool, &auth, &c, &p).await;
    let down = with(&c, |v| {
        v["version"] = json!(2);
        v["protected"] = json!(false);
    });
    publish(&pool, &auth, &down, &with(&p, |v| v["version"] = json!(2))).await;
    let b = reg(&pool, &auth).await;
    assert_eq!(tools(&b).len(), 0);
    let u = &b["unprotected_tools"];
    assert_eq!(u.as_array().unwrap().len(), 1, "{b}");
    assert_eq!(u[0]["tool_name"], "pay");
    assert_eq!(u[0]["server_slug"], "synthetic");
    assert_eq!(u[0]["contract_version"], 2);
    assert_eq!(b["observed_only_servers"].as_array().unwrap().len(), 1);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_digest_ignores_last_used_at() {
    let (pool, auth, _, _) = setup().await;
    let k = key(&pool, &auth.tenant_id, "a", None).await;
    let before = reg(&pool, &auth).await;
    pool.get()
        .await
        .unwrap()
        .execute("UPDATE api_keys SET last_used_at=now() WHERE id=$1", &[&k])
        .await
        .unwrap();
    let after = reg(&pool, &auth).await;
    assert!(agent(&before, k)["last_used_at"].is_null());
    assert!(agent(&after, k)["last_used_at"].is_string());
    assert_eq!(before["register_digest"], after["register_digest"]);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_rejects_api_key_caller() {
    let (pool, tenant) = fixture().await;
    let auth = claims(&tenant); // AuthMethod::ApiKey: an agent key must not read the register
    let (s, _) = get_as(&pool, &auth, M::On, "/v1/action-authority").await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_no_entitlement_cache_is_flag_off() {
    let (pool, auth, c, p) = setup().await;
    publish(&pool, &auth, &c, &p).await;
    let (s, b) = get_as(&pool, &auth, M::NoCache, "/v1/action-authority").await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(b["workspace"]["action_control"], false);
    assert_eq!(b["protected_tools"], json!([]));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_entitlement_outage_503() {
    let (pool, auth, _, _) = setup().await;
    let (s, b) = get_as(&pool, &auth, M::Outage, "/v1/action-authority").await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(b["error"], "register_unavailable");
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_rejects_tampered_policy_hash() {
    let (pool, auth, c, p) = setup().await;
    publish(&pool, &auth, &c, &p).await;
    let db = pool.get().await.unwrap();
    db.batch_execute("ALTER TABLE action_policies DISABLE TRIGGER action_policy_immutable")
        .await
        .unwrap();
    db.execute(
        "UPDATE action_policies SET policy_hash=repeat('a',64) WHERE tenant_id=$1",
        &[auth.tenant_id.as_uuid()],
    )
    .await
    .unwrap();
    let (s, b) = get_as(&pool, &auth, M::On, "/v1/action-authority").await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{b}");
    assert_eq!(b["error"], "register_unavailable");
}

// ---- ACT-15b: register as of a past time -------------------------------------------------
use chrono::{DateTime, Duration, SecondsFormat, SubsecRound, Utc};

/// A fixed whole-second instant well in the past; history is re-timed relative to it.
fn base() -> DateTime<Utc> {
    (Utc::now() - Duration::hours(48)).trunc_subsecs(0)
}
fn ts(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Micros, true)
}
async fn get_at(
    pool: &deadpool_postgres::Pool,
    auth: &crate::auth::Claims,
    t: DateTime<Utc>,
) -> (StatusCode, Value) {
    get_as(
        pool,
        auth,
        M::On,
        &format!("/v1/action-authority?as_of={}", ts(t)),
    )
    .await
}
async fn at(pool: &deadpool_postgres::Pool, auth: &crate::auth::Claims, t: DateTime<Utc>) -> Value {
    let (s, b) = get_at(pool, auth, t).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    b
}
/// Give every ledger row of `t` a distinct, controlled `event_time` (`base + seq hours`) and
/// return the `policy_activated` seqs in order. The append-only trigger is disabled for the
/// test database only: real rows can never be re-timed.
async fn retime(pool: &deadpool_postgres::Pool, t: &TenantId, base: DateTime<Utc>) -> Vec<i64> {
    let db = pool.get().await.unwrap();
    db.batch_execute("ALTER TABLE audit_log_rows DISABLE TRIGGER action_evidence_immutable")
        .await
        .unwrap();
    db.execute(
        "UPDATE audit_log_rows SET event_time=$2::timestamptz + seq::float8 * interval '1 hour' WHERE tenant_id=$1",
        &[t.as_uuid(), &base],
    )
    .await
    .unwrap();
    db.query(
        "SELECT seq FROM audit_log_rows WHERE tenant_id=$1 AND event_type='policy_activated' ORDER BY seq",
        &[t.as_uuid()],
    )
    .await
    .unwrap()
    .iter()
    .map(|r| r.get(0))
    .collect()
}
/// Time of ledger row `seq` plus 30 minutes: strictly after it, before the next hour's row.
fn after(base: DateTime<Utc>, seq: i64) -> DateTime<Utc> {
    base + Duration::hours(seq) + Duration::minutes(30)
}
/// Policy v1 then v2 (different rules), re-timed. Returns (base, seqs of v1 and v2).
async fn history(
    pool: &deadpool_postgres::Pool,
    auth: &crate::auth::Claims,
    c: &str,
    p: &str,
) -> (DateTime<Utc>, Vec<i64>) {
    publish(pool, auth, c, p).await;
    publish(
        pool,
        auth,
        c,
        &with(p, |v| {
            v["version"] = json!(2);
            v["rules"] = json!([{"id":"deny-two","when":[],"decision":"deny"}]);
        }),
    )
    .await;
    let b = base();
    let seqs = retime(pool, &auth.tenant_id, b).await;
    assert_eq!(seqs.len(), 2);
    (b, seqs)
}
/// Set a key's lifecycle columns directly (synthetic history).
async fn life(
    pool: &deadpool_postgres::Pool,
    id: Uuid,
    created: DateTime<Utc>,
    revoked: Option<DateTime<Utc>>,
    expires: Option<DateTime<Utc>>,
) {
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE api_keys SET created_at=$2, revoked_at=$3, expires_at=$4 WHERE id=$1",
            &[&id, &created, &revoked, &expires],
        )
        .await
        .unwrap();
}
fn has_key(b: &Value, id: Uuid) -> bool {
    b["agents"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["key_id"] == id.to_string())
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_without_as_of_is_unchanged() {
    let (pool, auth, c, p) = setup().await;
    publish(&pool, &auth, &c, &p).await;
    let k = key(&pool, &auth.tenant_id, "shape", None).await;
    let b = reg(&pool, &auth).await;
    for k in [
        "as_of",
        "as_of_seq",
        "key_attributes",
        "key_membership",
        "current",
    ] {
        assert!(b.get(k).is_none(), "{k} must not appear without as_of");
    }
    // One full entry of each kind: today's shape, current values in place.
    let sorted = |v: &Value| {
        let mut k: Vec<String> = v.as_object().unwrap().keys().cloned().collect();
        k.sort();
        k
    };
    assert_eq!(
        sorted(&b["workspace"]),
        ["action_control", "paused_at", "tenant_id"]
    );
    assert_eq!(
        sorted(&tools(&b)[0]),
        [
            "agents",
            "default",
            "policy_hash",
            "policy_id",
            "policy_version",
            "publisher_sub",
            "rules",
            "server_id",
            "server_slug",
            "tool_name",
            "tool_ref"
        ]
    );
    assert_eq!(tools(&b)[0]["server_slug"], "synthetic");
    assert_eq!(b["workspace"]["action_control"], true);
    assert_eq!(
        sorted(agent(&b, k)),
        [
            "budget_usd_monthly",
            "created_at",
            "expires_at",
            "key_id",
            "key_prefix",
            "last_used_at",
            "minted_by",
            "name",
            "protected_tools_in_policy_scope",
            "rate_limit_rpm",
            "scope"
        ]
    );
    assert_eq!(
        agent(&b, k)["protected_tools_in_policy_scope"],
        json!([tools(&b)[0]["tool_ref"]])
    );
    let mut keys: Vec<&String> = b.as_object().unwrap().keys().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "agents",
            "agents_truncated",
            "approval",
            "generated_at",
            "observed_only_servers",
            "protected_tools",
            "register_digest",
            "unprotected_tools",
            "workspace"
        ]
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_shows_policy_active_then() {
    let (pool, auth, c, p) = setup().await;
    let (b0, seqs) = history(&pool, &auth, &c, &p).await;
    let b = at(&pool, &auth, after(b0, seqs[0])).await;
    assert_eq!(tools(&b).len(), 1);
    assert_eq!(tools(&b)[0]["policy_version"], 1);
    assert_eq!(tools(&b)[0]["rules"][0]["id"], "deny");
    // The current register is unaffected by the history query.
    assert_eq!(
        reg(&pool, &auth).await["protected_tools"][0]["policy_version"],
        2
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_after_change_shows_new_policy() {
    let (pool, auth, c, p) = setup().await;
    let (b0, seqs) = history(&pool, &auth, &c, &p).await;
    let b = at(&pool, &auth, after(b0, seqs[1])).await;
    assert_eq!(tools(&b)[0]["policy_version"], 2);
    assert_eq!(tools(&b)[0]["rules"][0]["id"], "deny-two");
    let stored: String = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT policy_hash FROM action_policies WHERE tenant_id=$1 AND version=2",
            &[auth.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(tools(&b)[0]["policy_hash"], stored);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_lists_key_before_revocation() {
    let (pool, auth, _, _) = setup().await;
    let b0 = base();
    let k = key(&pool, &auth.tenant_id, "gone", None).await;
    let r = b0 + Duration::hours(10);
    life(&pool, k, b0, Some(r), None).await;
    assert!(has_key(&at(&pool, &auth, r - Duration::hours(1)).await, k));
    assert!(!has_key(&at(&pool, &auth, r + Duration::hours(1)).await, k));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_seq_matches_ledger() {
    let (pool, auth, c, p) = setup().await;
    let (b0, seqs) = history(&pool, &auth, &c, &p).await;
    for (i, want) in seqs.iter().enumerate() {
        let t = after(b0, *want);
        let direct: Option<i64> = pool
            .get()
            .await
            .unwrap()
            .query_one(
                "SELECT max(seq) FROM audit_log_rows WHERE tenant_id=$1 AND event_type='policy_activated' AND event_time<=$2",
                &[auth.tenant_id.as_uuid(), &t],
            )
            .await
            .unwrap()
            .get(0);
        let b = at(&pool, &auth, t).await;
        assert_eq!(direct, Some(*want), "step {i}");
        assert_eq!(b["as_of_seq"], json!(want));
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_before_history_is_empty() {
    let (pool, auth, c, p) = setup().await;
    let (b0, _) = history(&pool, &auth, &c, &p).await;
    let b = at(&pool, &auth, b0 - Duration::hours(1)).await;
    assert_eq!(b["protected_tools"], json!([]));
    assert_eq!(b["unprotected_tools"], json!([]));
    assert!(b["as_of_seq"].is_null());
    assert!(b.get("as_of_seq").is_some());
    // The workspace's server was created after T, so it is not listed either.
    assert_eq!(b["observed_only_servers"], json!([]));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_shows_downgrade() {
    let (pool, auth, c, p) = setup().await;
    publish(&pool, &auth, &c, &p).await;
    let down = with(&c, |v| {
        v["version"] = json!(2);
        v["protected"] = json!(false);
    });
    publish(&pool, &auth, &down, &with(&p, |v| v["version"] = json!(2))).await;
    let b0 = base();
    let seqs = retime(&pool, &auth.tenant_id, b0).await;
    let before = at(&pool, &auth, after(b0, seqs[0])).await;
    assert_eq!(tools(&before).len(), 1);
    assert_eq!(before["unprotected_tools"], json!([]));
    let later = at(&pool, &auth, after(b0, seqs[1])).await;
    assert_eq!(tools(&later).len(), 0);
    let u = &later["unprotected_tools"];
    assert_eq!(u.as_array().unwrap().len(), 1, "{later}");
    assert_eq!(u[0]["tool_name"], "pay");
    assert_eq!(u[0]["contract_version"], 2);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_includes_later_archived_server() {
    let (pool, auth, c, p) = setup().await;
    publish(&pool, &auth, &c, &p).await;
    let b0 = base();
    let seqs = retime(&pool, &auth.tenant_id, b0).await;
    let archived = b0 + Duration::hours(20);
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE mcp_servers SET archived_at=$2 WHERE tenant_id=$1",
            &[auth.tenant_id.as_uuid(), &archived],
        )
        .await
        .unwrap();
    let before = at(&pool, &auth, after(b0, seqs[0])).await;
    let sid = tools(&before)[0]["server_id"].as_str().unwrap().to_owned();
    assert_eq!(before["current"]["server_slugs"][&sid], "synthetic");
    let past = at(&pool, &auth, archived + Duration::hours(1)).await;
    assert!(past["current"]["server_slugs"][&sid].is_null());
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_in_digest() {
    let (pool, auth, c, p) = setup().await;
    let (b0, _) = history(&pool, &auth, &c, &p).await;
    // Both instants precede all history, so the state is equal: only as_of differs.
    let (t1, t2) = (b0 - Duration::hours(3), b0 - Duration::hours(2));
    let (a, b) = (at(&pool, &auth, t1).await, at(&pool, &auth, t2).await);
    assert_ne!(a["register_digest"], b["register_digest"]);
    assert_eq!(
        a["register_digest"],
        at(&pool, &auth, t1).await["register_digest"]
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_labels_key_attributes_current() {
    let (pool, auth, _, _) = setup().await;
    let t = base();
    let b = at(&pool, &auth, t).await;
    assert_eq!(b["key_attributes"], "current");
    assert_eq!(
        b["as_of"]
            .as_str()
            .unwrap()
            .parse::<DateTime<Utc>>()
            .unwrap(),
        t
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_future_rejected() {
    let (pool, auth, _, _) = setup().await;
    let (s, b) = get_at(&pool, &auth, Utc::now() + Duration::hours(1)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(b["error"], "as_of_in_future");
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_malformed_rejected() {
    let (pool, auth, _, _) = setup().await;
    for bad in ["garbage", "", "2026-13-45T00:00:00Z"] {
        let (s, b) = get_as(
            &pool,
            &auth,
            M::On,
            &format!("/v1/action-authority?as_of={bad}"),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(b["error"], "as_of_invalid", "{bad}");
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_without_zone_rejected() {
    let (pool, auth, _, _) = setup().await;
    for bad in ["2026-01-01T00:00:00", "2026-01-01", "2026-01-01T00:00:00.5"] {
        let (s, b) = get_as(
            &pool,
            &auth,
            M::On,
            &format!("/v1/action-authority?as_of={bad}"),
        )
        .await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad}");
        assert_eq!(b["error"], "as_of_invalid", "{bad}");
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_excludes_key_created_later() {
    let (pool, auth, _, _) = setup().await;
    let b0 = base();
    let k = key(&pool, &auth.tenant_id, "late", None).await;
    let created = b0 + Duration::hours(10);
    life(&pool, k, created, None, None).await;
    assert!(!has_key(
        &at(&pool, &auth, created - Duration::hours(1)).await,
        k
    ));
    assert!(has_key(
        &at(&pool, &auth, created + Duration::hours(1)).await,
        k
    ));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_excludes_key_revoked_at_t() {
    let (pool, auth, _, _) = setup().await;
    let b0 = base();
    let k = key(&pool, &auth.tenant_id, "edge", None).await;
    let r = b0 + Duration::hours(10);
    life(&pool, k, b0, Some(r), None).await;
    assert!(!has_key(&at(&pool, &auth, r).await, k));
    assert!(has_key(
        &at(&pool, &auth, r - Duration::microseconds(1)).await,
        k
    ));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_excludes_expired_key() {
    let (pool, auth, _, _) = setup().await;
    let b0 = base();
    let k = key(&pool, &auth.tenant_id, "exp", None).await;
    let e = b0 + Duration::hours(10);
    life(&pool, k, b0, None, Some(e)).await;
    assert!(has_key(&at(&pool, &auth, e - Duration::hours(1)).await, k));
    assert!(!has_key(&at(&pool, &auth, e + Duration::hours(1)).await, k));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_hash_mismatch_fails_closed() {
    let (pool, auth, c, p) = setup().await;
    let (b0, seqs) = history(&pool, &auth, &c, &p).await;
    let db = pool.get().await.unwrap();
    db.batch_execute("ALTER TABLE action_policies DISABLE TRIGGER action_policy_immutable")
        .await
        .unwrap();
    db.execute(
        "UPDATE action_policies SET policy_hash=repeat('a',64) WHERE tenant_id=$1 AND version=1",
        &[auth.tenant_id.as_uuid()],
    )
    .await
    .unwrap();
    let (s, b) = get_at(&pool, &auth, after(b0, seqs[0])).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{b}");
    assert_eq!(b["error"], "register_unavailable");
    // v2 is untouched, so a time that resolves to v2 still answers.
    assert_eq!(
        at(&pool, &auth, after(b0, seqs[1])).await["protected_tools"][0]["policy_version"],
        2
    );
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_malformed_ledger_row_fails_closed() {
    let (pool, auth, c, p) = setup().await;
    let (b0, seqs) = history(&pool, &auth, &c, &p).await;
    for bad in [
        "not json",
        r#"{"body":{"event_type":"policy_activated"}}"#,
        "[]",
        "\"x\"",
        "1",
        "{}",
    ] {
        let res = pool
            .get()
            .await
            .unwrap()
            .execute(
                "UPDATE audit_log_rows SET payload=$3 WHERE tenant_id=$1 AND seq=$2",
                &[auth.tenant_id.as_uuid(), &seqs[0], &bad],
            )
            .await;
        if bad == "not json" {
            // Migration 0090 indexes `(payload::jsonb)` for the action-ledger event types, so
            // Postgres itself refuses a non-JSON payload for them: this shape cannot be stored.
            let err = res.expect_err("0090's expression index must refuse a non-JSON payload");
            assert_eq!(
                err.code(),
                Some(&tokio_postgres::error::SqlState::INVALID_TEXT_REPRESENTATION)
            );
            continue;
        }
        res.unwrap();
        rehash(&pool, &auth.tenant_id, seqs[0]).await;
        let (s, b) = get_at(&pool, &auth, after(b0, seqs[0])).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{bad}: {b}");
        assert_eq!(b["error"], "register_unavailable");
    }
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_ignores_other_tenant_ledger() {
    let (pool, auth, c, p) = setup().await;
    publish(&pool, &auth, &c, &p).await;
    let other = TenantId::from_jwt_claim(Uuid::new_v4());
    crate::db::tenants::create(&pool, *other.as_uuid(), "synthetic-other", "free")
        .await
        .unwrap();
    let server = Uuid::new_v4();
    pool.get().await.unwrap().execute("INSERT INTO mcp_servers(id,tenant_id,slug,name,url,transport,auth_mode) VALUES ($1,$2,'theirs','Theirs','https://example.invalid','streamable_http','none')", &[&server, other.as_uuid()]).await.unwrap();
    let mut theirs = auth.clone();
    theirs.tenant_id = other.clone();
    let tc = with(&c, |v| {
        v["tool_ref"] = json!(Uuid::new_v4());
        v["server_id"] = json!(server);
        v["tool_name"] = json!("refund");
    });
    let tp = with(&p, |v| v["policy_id"] = json!(Uuid::new_v4()));
    publish(&pool, &theirs, &tc, &tp).await;
    publish(&pool, &theirs, &tc, &with(&tp, |v| v["version"] = json!(2))).await;
    let b0 = base();
    let mine = retime(&pool, &auth.tenant_id, b0).await;
    let _ = retime(&pool, &other, b0).await;
    let b = at(&pool, &auth, b0 + Duration::hours(40)).await;
    assert_eq!(tools(&b).len(), 1);
    assert_eq!(tools(&b)[0]["tool_name"], "pay");
    assert_eq!(b["as_of_seq"], json!(mine[0]));
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_rejects_api_key_caller() {
    let (pool, tenant) = fixture().await;
    let auth = claims(&tenant);
    let (s, _) = get_at(&pool, &auth, base()).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_flag_off_reports_ledger() {
    let (pool, auth, c, p) = setup().await;
    let (b0, seqs) = history(&pool, &auth, &c, &p).await;
    let k = key(&pool, &auth.tenant_id, "k", None).await;
    life(&pool, k, b0, None, None).await;
    let uri = format!("/v1/action-authority?as_of={}", ts(after(b0, seqs[0])));
    let (s, b) = get_as(&pool, &auth, M::Off, &uri).await;
    assert_eq!(s, StatusCode::OK, "{b}");
    assert_eq!(tools(&b)[0]["policy_version"], 1);
    // Permissions at T come from the ledger, not from today's flag.
    assert_eq!(
        agent(&b, k)["protected_tools_in_policy_scope"],
        json!([tools(&b)[0]["tool_ref"]])
    );
}

/// Recompute a test row's hash with the ledger's own function, so only the tampered field differs.
async fn rehash(pool: &deadpool_postgres::Pool, t: &TenantId, seq: i64) {
    let db = pool.get().await.unwrap();
    let r = db
        .query_one(
            "SELECT payload, actor, prev_hash FROM audit_log_rows WHERE tenant_id=$1 AND seq=$2",
            &[t.as_uuid(), &seq],
        )
        .await
        .unwrap();
    let prev = crate::db::ledger::decode_hash_hex(r.get(2)).unwrap();
    let h = crate::audit_format::row_hash_v2(
        &prev,
        t,
        seq as u64,
        "policy_activated",
        r.get(1),
        r.get(0),
    );
    db.execute(
        "UPDATE audit_log_rows SET row_hash=$3 WHERE tenant_id=$1 AND seq=$2",
        &[t.as_uuid(), &seq, &hex::encode(h)],
    )
    .await
    .unwrap();
}
/// Edit a ledger payload and keep the row hash valid (the hash check is tested separately).
async fn tamper(pool: &deadpool_postgres::Pool, t: &TenantId, seq: i64, from: &str, to: &str) {
    pool.get().await.unwrap().execute(
        "UPDATE audit_log_rows SET payload=replace(payload,$3,$4) WHERE tenant_id=$1 AND seq=$2 AND event_type='policy_activated'",
        &[t.as_uuid(), &seq, &from, &to],
    ).await.unwrap();
    rehash(pool, t, seq).await;
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_uses_chain_prefix_when_times_disagree() {
    let (pool, auth, c, p) = setup().await;
    publish(&pool, &auth, &c, &p).await;
    let c2 = with(&c, |v| {
        v["tool_ref"] = json!(Uuid::new_v4());
        v["tool_name"] = json!("refund");
    });
    publish(
        &pool,
        &auth,
        &c2,
        &with(&p, |v| v["policy_id"] = json!(Uuid::new_v4())),
    )
    .await;
    let b0 = base();
    let seqs = retime(&pool, &auth.tenant_id, b0).await;
    // Row 0 now carries a time AFTER T while row 1 (later in the chain) is before T.
    pool.get()
        .await
        .unwrap()
        .execute(
            "UPDATE audit_log_rows SET event_time=$3 WHERE tenant_id=$1 AND seq=$2",
            &[
                auth.tenant_id.as_uuid(),
                &seqs[0],
                &(b0 + Duration::hours(30)),
            ],
        )
        .await
        .unwrap();
    let b = at(&pool, &auth, b0 + Duration::hours(2)).await;
    // Replay of the chain to as_of_seq: every activation with seq <= S.
    assert_eq!(b["as_of_seq"], json!(seqs[1]));
    let replayed: i64 = pool.get().await.unwrap().query_one(
        "SELECT count(DISTINCT payload::jsonb->'body'->>'tool_ref') FROM audit_log_rows WHERE tenant_id=$1 AND event_type='policy_activated' AND seq<=$2",
        &[auth.tenant_id.as_uuid(), &seqs[1]],
    ).await.unwrap().get(0);
    let mut names: Vec<&str> = tools(&b)
        .iter()
        .map(|t| t["tool_name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["pay", "refund"]);
    assert_eq!(tools(&b).len() as i64, replayed);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_labels_current_values() {
    let (pool, auth, c, p) = setup().await;
    publish(&pool, &auth, &c, &p).await;
    let k = key(&pool, &auth.tenant_id, "k", None).await;
    let b0 = base();
    let seqs = retime(&pool, &auth.tenant_id, b0).await;
    life(&pool, k, b0, None, None).await;
    let t = after(b0, seqs[0]);
    let b = at(&pool, &auth, t).await;
    assert_eq!(b["enforcement_at_as_of"], "not_recorded");
    assert_eq!(b["key_membership"], "current_expires_at");
    assert!(b["workspace"].get("paused_at").is_none());
    assert!(b["workspace"].get("action_control").is_none());
    assert!(tools(&b)[0].get("server_slug").is_none());
    assert!(agent(&b, k).get("last_used_at").is_none());
    let sid = tools(&b)[0]["server_id"].as_str().unwrap().to_owned();
    let cur = &b["current"];
    assert_eq!(cur["action_control"], true);
    assert!(cur.get("paused_at").is_some());
    assert_eq!(cur["server_slugs"][&sid], "synthetic");
    assert!(cur["last_used_at"].get(k.to_string()).is_some());
    // Current values move without moving the digest.
    let db = pool.get().await.unwrap();
    db.execute("UPDATE api_keys SET last_used_at=now() WHERE id=$1", &[&k])
        .await
        .unwrap();
    db.execute(
        "UPDATE mcp_servers SET slug='renamed' WHERE tenant_id=$1",
        &[auth.tenant_id.as_uuid()],
    )
    .await
    .unwrap();
    let b2 = at(&pool, &auth, t).await;
    assert_eq!(b2["current"]["server_slugs"][&sid], "renamed");
    assert!(b2["current"]["last_used_at"][k.to_string()].is_string());
    assert_eq!(b["register_digest"], b2["register_digest"]);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_ledger_hash_mismatch_fails_closed() {
    let (pool, auth, c, p) = setup().await;
    let (b0, seqs) = history(&pool, &auth, &c, &p).await;
    // The stored policy row stays self-consistent; only the ledger's copy of the hash changes.
    let stored: String = pool
        .get()
        .await
        .unwrap()
        .query_one(
            "SELECT policy_hash FROM action_policies WHERE tenant_id=$1 AND version=1",
            &[auth.tenant_id.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    tamper(
        &pool,
        &auth.tenant_id,
        seqs[0],
        &format!("\"policy_hash\":\"{stored}\""),
        &format!("\"policy_hash\":\"{}\"", "b".repeat(64)),
    )
    .await;
    let (s, b) = get_at(&pool, &auth, after(b0, seqs[0])).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{b}");
    assert_eq!(b["error"], "register_unavailable");
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_contract_mismatch_fails_closed() {
    let (pool, auth, c, p) = setup().await;
    let (b0, seqs) = history(&pool, &auth, &c, &p).await;
    let t = after(b0, seqs[0]);
    // Ledger says unprotected, the stored contract says protected.
    tamper(
        &pool,
        &auth.tenant_id,
        seqs[0],
        "\"protected\":true",
        "\"protected\":false",
    )
    .await;
    assert_eq!(
        get_at(&pool, &auth, t).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    tamper(
        &pool,
        &auth.tenant_id,
        seqs[0],
        "\"protected\":false",
        "\"protected\":true",
    )
    .await;
    assert_eq!(get_at(&pool, &auth, t).await.0, StatusCode::OK);
    // Stored contract hash no longer matches its own body (and the ledger's hash).
    let db = pool.get().await.unwrap();
    db.batch_execute("ALTER TABLE action_tool_contracts DISABLE TRIGGER action_contract_immutable")
        .await
        .unwrap();
    db.execute(
        "UPDATE action_tool_contracts SET contract_hash=repeat('c',64) WHERE tenant_id=$1",
        &[auth.tenant_id.as_uuid()],
    )
    .await
    .unwrap();
    let (s, b) = get_at(&pool, &auth, t).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{b}");
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_ledger_tenant_mismatch_fails_closed() {
    let (pool, auth, c, p) = setup().await;
    let (b0, seqs) = history(&pool, &auth, &c, &p).await;
    // A payload that names no tenant at all is not accepted (row 1; row 0 is untouched).
    pool.get().await.unwrap().execute(
        "UPDATE audit_log_rows SET payload=((payload::jsonb) - 'tenant_id')::text WHERE tenant_id=$1 AND seq=$2",
        &[auth.tenant_id.as_uuid(), &seqs[1]],
    ).await.unwrap();
    rehash(&pool, &auth.tenant_id, seqs[1]).await;
    let (s, b) = get_at(&pool, &auth, after(b0, seqs[1])).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{b}");
    // Row 0 names another tenant; a read that stops at row 0 sees only it.
    let me = format!("\"tenant_id\":\"{}\"", auth.tenant_id);
    let foreign = format!("\"tenant_id\":\"{}\"", Uuid::new_v4());
    tamper(&pool, &auth.tenant_id, seqs[0], &me, &foreign).await;
    let (s, b) = get_at(&pool, &auth, after(b0, seqs[0])).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{b}");
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_too_recent_rejected() {
    let (pool, auth, _, _) = setup().await;
    let (s, b) = get_at(&pool, &auth, Utc::now() - Duration::seconds(10)).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(b["error"], "as_of_too_recent");
    let (s, _) = get_at(&pool, &auth, Utc::now() - Duration::seconds(200)).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_digest_independent_of_current_flag() {
    let (pool, auth, c, p) = setup().await;
    let (b0, seqs) = history(&pool, &auth, &c, &p).await;
    let k = key(&pool, &auth.tenant_id, "k", None).await;
    life(&pool, k, b0, None, None).await;
    let uri = format!("/v1/action-authority?as_of={}", ts(after(b0, seqs[1])));
    let (s1, on) = get_as(&pool, &auth, M::On, &uri).await;
    let (s2, off) = get_as(&pool, &auth, M::Off, &uri).await;
    assert_eq!((s1, s2), (StatusCode::OK, StatusCode::OK));
    assert_eq!(on["register_digest"], off["register_digest"]);
    assert_eq!(
        agent(&on, k)["protected_tools_in_policy_scope"],
        agent(&off, k)["protected_tools_in_policy_scope"]
    );
    assert_eq!(
        agent(&off, k)["protected_tools_in_policy_scope"],
        json!([tools(&off)[0]["tool_ref"]])
    );
    assert_eq!(on["current"]["action_control"], true);
    assert_eq!(off["current"]["action_control"], false);
}
#[tokio::test]
#[ignore = "requires isolated Postgres"]
async fn pg_register_as_of_tampered_payload_fails_row_hash() {
    let (pool, auth, c, p) = setup().await;
    let (b0, seqs) = history(&pool, &auth, &c, &p).await;
    // A field nothing else cross-checks: policy and contract rows still match the payload.
    pool.get().await.unwrap().execute(
        "UPDATE audit_log_rows SET payload=replace(payload,'\"schema_version\":1','\"schema_version\":7') WHERE tenant_id=$1 AND seq=$2",
        &[auth.tenant_id.as_uuid(), &seqs[0]],
    ).await.unwrap();
    let (s, b) = get_at(&pool, &auth, after(b0, seqs[0])).await;
    assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE, "{b}");
    assert_eq!(b["error"], "register_unavailable");
}

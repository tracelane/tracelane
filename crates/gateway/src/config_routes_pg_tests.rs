//! `OG-61a` — `GET /v1/config/export` against REAL Postgres (`#[ignore]`d; run with
//! `POSTGRES_TEST_URL` set, filter `config_routes_pg_tests`). Each test takes a fresh,
//! fully migrated database. Spec: `specs/OG-61-config-as-code.md` §10.

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use serde_json::{Value, json};
use tower::ServiceExt as _;
use tracelane_shared::TenantId;

use crate::auth::scope::KeyScope;
use crate::auth::{AuthMethod, Claims, Role};
use crate::db::admin_security::AdminAccess;
use crate::entitlement_cache::b409_fixture::{fresh_migrated_pool, seed_v3_then_v4};

/// A fresh, migrated database that also holds the `builder` plan catalog and allowances
/// (`GET /v1/data-controls` reads the stored retention through the plan join).
async fn setup() -> crate::db::DbPool {
    let pool = fresh_migrated_pool().await;
    seed_v3_then_v4(&pool).await;
    pool
}

const CANARY_CHANNEL_TARGET: &str = "CANARY-channel-target-91c2e7";
const CANARY_CHANNEL_SEALED: &str = "CANARY-channel-sealed-5b0d44";
const CANARY_MCP_CREDENTIAL: &str = "CANARY-mcp-credential-3e8a19";
const CANARY_PROVIDER_KEY: &str = "CANARY-provider-key-c47f02";
const CANARY_API_KEY: &str = "CANARY-api-key-a1d9b6";

async fn tenant(c: &deadpool_postgres::Client, label: &str) -> TenantId {
    let org = format!("org_og61_{label}_{}", uuid::Uuid::new_v4().simple());
    let id: uuid::Uuid = c
        .query_one(
            "INSERT INTO tenants (workos_org_id, name, plan) VALUES ($1, $2, 'builder'::text::plan) RETURNING id",
            &[&org, &label],
        )
        .await
        .expect("insert tenant")
        .get(0);
    TenantId::from_jwt_claim(id)
}

fn who(t: &TenantId, auth_method: AuthMethod, role: Option<Role>) -> Claims {
    Claims {
        tenant_id: t.clone(),
        sub: "user_og61".into(),
        auth_method,
        role,
        key_scope: KeyScope::LegacyFullSurface,
        budget_usd_monthly: None,
        rate_limit_rpm: None,
        budget_reset: crate::spend::BudgetReset::Monthly,
        key_capture: None,
        governance: None,
    }
}

fn admin(t: &TenantId) -> Claims {
    who(t, AuthMethod::JwtBearer, Some(Role::Owner))
}

/// One export call as `claims`; returns the status and the raw response bytes.
async fn export(pool: &crate::db::DbPool, claims: Claims, query: &str) -> (StatusCode, Vec<u8>) {
    let _policy = crate::control_plane::test_overrides::Guard::new(
        Some(Ok(AdminAccess::default())),
        None,
        None,
    );
    let _claims = crate::auth::test_claims::Guard::set(claims);
    let resp = crate::config_routes::router(pool.clone())
        .oneshot(
            Request::get(format!("/v1/config/export{query}"))
                .header("authorization", "Bearer test-token-not-a-real-jwt")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1 << 22).await.unwrap().to_vec();
    (status, bytes)
}

fn json_of(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap_or_else(|e| {
        panic!("not JSON ({e}): {}", String::from_utf8_lossy(bytes));
    })
}

/// Rows for every exportable section plus a credential of every class the export must
/// never carry. `tag` keeps tenant A's and tenant B's names distinct.
async fn seed(c: &deadpool_postgres::Client, t: &TenantId, tag: &str, canaries: bool) {
    let id = t.as_uuid();
    let pause = "someone-paused-it";
    c.execute(
        "INSERT INTO workspace_controls (tenant_id, policy, paused_at, paused_by, pause_reason, \
           blocked_models, blocked_providers, blocked_end_users, updated_by) \
         VALUES ($1, $2, now(), $3, 'incident', $4, $5, $6, 'seed')",
        &[
            id,
            &json!({"limits": {"rpm": 100}, "budget": {"usd": 50}}),
            &pause,
            &vec![format!("{tag}-model-z"), format!("{tag}-model-a")],
            &vec![format!("{tag}-prov")],
            &vec![format!("{tag}-user-2"), format!("{tag}-user-1")],
        ],
    )
    .await
    .expect("workspace_controls");
    for (alias, target) in [("zeta", "gpt-4o"), ("alpha", "gpt-4o-mini")] {
        c.execute(
            "INSERT INTO model_aliases (tenant_id, alias, target_model, updated_by) \
             VALUES ($1, $2, $3, 'seed')",
            &[id, &format!("{tag}-{alias}"), &target],
        )
        .await
        .expect("model_aliases");
    }
    c.execute(
        "INSERT INTO workspace_failover (tenant_id, enabled, models, updated_by) \
         VALUES ($1, true, $2, 'seed')",
        &[
            id,
            &vec!["gpt-4o".to_owned(), "claude-3-5-sonnet-latest".to_owned()],
        ],
    )
    .await
    .expect("workspace_failover");
    c.execute(
        "INSERT INTO workspace_content_capture (tenant_id, input, output) VALUES ($1, true, false)",
        &[id],
    )
    .await
    .expect("workspace_content_capture");
    for (name, envs) in [
        ("Zulu", vec!["production"]),
        ("alpha", vec!["staging", "production"]),
    ] {
        c.execute(
            "INSERT INTO projects (tenant_id, name, environments) VALUES ($1, $2, $3)",
            &[id, &format!("{tag}-{name}"), &envs],
        )
        .await
        .expect("projects");
    }
    c.execute(
        "INSERT INTO spend_alert_channels (id, tenant_id, kind, name, target, secret_enc) \
         VALUES ($1, $2, 'webhook', $3, $4, $5)",
        &[
            &uuid::Uuid::new_v4(),
            id,
            &format!("{tag}-oncall"),
            &if canaries {
                format!("https://hooks.example.com/{CANARY_CHANNEL_TARGET}")
            } else {
                format!("https://hooks.example.com/{tag}")
            },
            &if canaries {
                CANARY_CHANNEL_SEALED
            } else {
                "sealed"
            },
        ],
    )
    .await
    .expect("spend_alert_channels");
    c.execute(
        "INSERT INTO tool_capabilities (tenant_id, tool_name, caps, def_hash) VALUES ($1, $2, 3, 'abc123')",
        &[id, &format!("{tag}-tool")],
    )
    .await
    .expect("tool_capabilities");
    c.execute(
        "INSERT INTO mcp_tool_rules (tenant_id, tool_glob, action, reason, created_by) \
         VALUES ($1, $2, 'deny', 'no shell', 'seed')",
        &[id, &format!("{tag}-shell*")],
    )
    .await
    .expect("mcp_tool_rules");
    c.execute(
        "INSERT INTO guardrail_policies (tenant_id, scope, scope_id, policy, updated_by) \
         VALUES ($1, 'workspace', $1, $2, 'seed')",
        &[
            id,
            &json!({"rails": {"R5_format": {"enabled": true}}, "tag": tag}),
        ],
    )
    .await
    .expect("guardrail_policies");
    c.execute(
        "INSERT INTO workspace_routing (tenant_id, doc, version, updated_by) VALUES ($1, $2, 1, 'seed')",
        &[id, &json!({"virtual_models": {}, "tag": tag})],
    )
    .await
    .expect("workspace_routing");
    c.execute(
        "INSERT INTO workspace_data_controls (tenant_id, retention_days, updated_by) VALUES ($1, 30, 'seed')",
        &[id],
    )
    .await
    .expect("workspace_data_controls");
    if canaries {
        c.execute(
            "INSERT INTO mcp_servers (tenant_id, slug, name, url, transport, auth_mode, credential_ct) \
             VALUES ($1, 'github', 'GitHub', 'https://mcp.example.com', 'streamable_http', 'gateway_held', $2)",
            &[id, &CANARY_MCP_CREDENTIAL],
        )
        .await
        .expect("mcp_servers");
        c.execute(
            "INSERT INTO provider_keys (tenant_id, provider_id, ciphertext_b64, last4) \
             VALUES ($1, 'openai', $2, 'f02a')",
            &[id, &CANARY_PROVIDER_KEY],
        )
        .await
        .expect("provider_keys");
        c.execute(
            "INSERT INTO api_keys (tenant_id, name, key_hash, key_prefix, lookup_hash) \
             VALUES ($1, 'ci-key', $2, 'tlane_a1d9', $3)",
            &[id, &CANARY_API_KEY, &CANARY_API_KEY.as_bytes()],
        )
        .await
        .expect("api_keys");
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    String::from_utf8_lossy(haystack).contains(needle)
}

const ALL_SECTIONS: [&str; 12] = [
    "blocks",
    "capture",
    "data_controls",
    "failover",
    "guardrail_policy",
    "mcp_tool_rules",
    "model_aliases",
    "projects",
    "routing",
    "spend_alert_channels",
    "tool_pins",
    "workspace_policy",
];

#[tokio::test]
#[ignore = "needs POSTGRES_TEST_URL — run with it set, filter config_routes_pg_tests"]
async fn config_export_is_canonical_and_stable() {
    let pool = setup().await;
    let c = pool.get().await.unwrap();
    let t = tenant(&c, "stable").await;
    seed(&c, &t, "s", false).await;

    let (s1, b1) = export(&pool, admin(&t), "").await;
    assert_eq!(s1, StatusCode::OK, "{}", String::from_utf8_lossy(&b1));
    let (s2, b2) = export(&pool, admin(&t), "").await;
    assert_eq!(s2, StatusCode::OK);
    let (d1, d2) = (json_of(&b1), json_of(&b2));

    assert_eq!(d1["schema"], "tracelane.config/v1");
    let mut names: Vec<&str> = d1["sections"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    names.sort_unstable();
    assert_eq!(names, ALL_SECTIONS);
    // The hash is recomputed here from the document, independently of the route.
    let recomputed =
        blake3::hash(crate::audit_format::canonical_payload(&d1["sections"]).as_bytes())
            .to_hex()
            .to_string();
    assert_eq!(d1["version"], recomputed.as_str());
    assert_eq!(
        d1["version"], d2["version"],
        "an unchanged workspace keeps its version"
    );
    assert!(
        chrono::DateTime::parse_from_rfc3339(d1["exported_at"].as_str().unwrap()).is_ok(),
        "exported_at is RFC 3339"
    );

    // Lists are sorted by their natural key (projects case-folded); failover order is meaning.
    let sec = &d1["sections"];
    let project_names: Vec<&str> = sec["projects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap())
        .collect();
    assert_eq!(project_names, ["s-alpha", "s-Zulu"]);
    let aliases: Vec<&str> = sec["model_aliases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["alias"].as_str().unwrap())
        .collect();
    assert_eq!(aliases, ["s-alpha", "s-zeta"]);
    assert_eq!(sec["blocks"]["models"], json!(["s-model-a", "s-model-z"]));
    assert_eq!(sec["blocks"]["end_users"], json!(["s-user-1", "s-user-2"]));
    assert_eq!(
        sec["failover"]["models"],
        json!(["gpt-4o", "claude-3-5-sonnet-latest"])
    );
    assert_eq!(sec["data_controls"]["retention_days"], 30);
    assert_eq!(sec["capture"], json!({"input": true, "output": false}));
    // Pause state is an action, not configuration.
    assert!(!contains(&b1, "someone-paused-it"));
    let excluded: Vec<&str> = d1["excluded"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["what"].as_str().unwrap())
        .collect();
    assert!(excluded.contains(&"pause state"), "{excluded:?}");

    // A subset is a document of its own, with its own version.
    let (s3, b3) = export(&pool, admin(&t), "?sections=model_aliases,blocks").await;
    assert_eq!(s3, StatusCode::OK);
    let d3 = json_of(&b3);
    assert_eq!(d3["sections"].as_object().unwrap().len(), 2);
    assert_ne!(d3["version"], d1["version"]);

    // A real change moves the version.
    c.execute(
        "INSERT INTO model_aliases (tenant_id, alias, target_model, updated_by) VALUES ($1, 's-new', 'gpt-4o', 'seed')",
        &[t.as_uuid()],
    )
    .await
    .unwrap();
    let (_, b4) = export(&pool, admin(&t), "").await;
    assert_ne!(json_of(&b4)["version"], d1["version"]);
}

#[tokio::test]
#[ignore = "needs POSTGRES_TEST_URL — run with it set, filter config_routes_pg_tests"]
async fn config_export_never_contains_secret_canaries() {
    let pool = setup().await;
    let c = pool.get().await.unwrap();
    let t = tenant(&c, "canary").await;
    seed(&c, &t, "c", true).await;

    let (status, bytes) = export(&pool, admin(&t), "").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    for canary in [
        CANARY_CHANNEL_TARGET,
        CANARY_CHANNEL_SEALED,
        CANARY_MCP_CREDENTIAL,
        CANARY_PROVIDER_KEY,
        CANARY_API_KEY,
    ] {
        assert!(!contains(&bytes, canary), "{canary} leaked into the export");
    }
    // Not even the field names of a secret column.
    for column in [
        "credential_ct",
        "ciphertext",
        "secret_enc",
        "key_hash",
        "lookup_hash",
    ] {
        assert!(!contains(&bytes, column), "{column} appears in the export");
    }
    // The channel is present, by name, with a reference where its target would be.
    let doc = json_of(&bytes);
    assert_eq!(
        doc["sections"]["spend_alert_channels"],
        json!([{"kind": "webhook", "name": "c-oncall"}])
    );
    assert_eq!(
        doc["secret_refs"],
        json!(["spend_alert_channel:c-oncall.target"])
    );
}

#[tokio::test]
#[ignore = "needs POSTGRES_TEST_URL — run with it set, filter config_routes_pg_tests"]
async fn config_export_is_tenant_scoped() {
    let pool = setup().await;
    let c = pool.get().await.unwrap();
    let a = tenant(&c, "scope-a").await;
    let b = tenant(&c, "scope-b").await;
    seed(&c, &a, "tenant-a", false).await;
    seed(&c, &b, "tenant-b", false).await;

    let (status, bytes) = export(&pool, admin(&a), "").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    assert!(contains(&bytes, "tenant-a-alpha"));
    assert!(
        !contains(&bytes, "tenant-b"),
        "tenant B's rows appeared in tenant A's export"
    );
    let (status, bytes) = export(&pool, admin(&b), "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(contains(&bytes, "tenant-b-alpha"));
    assert!(
        !contains(&bytes, "tenant-a"),
        "tenant A's rows appeared in tenant B's export"
    );
}

#[tokio::test]
#[ignore = "needs POSTGRES_TEST_URL — run with it set, filter config_routes_pg_tests"]
async fn config_export_rejects_api_key_and_viewer() {
    let pool = setup().await;
    let c = pool.get().await.unwrap();
    let t = tenant(&c, "roles").await;
    seed(&c, &t, "r", false).await;

    for (label, claims) in [
        ("api key", who(&t, AuthMethod::ApiKey, None)),
        ("viewer", who(&t, AuthMethod::JwtBearer, Some(Role::Viewer))),
        (
            "developer",
            who(&t, AuthMethod::JwtBearer, Some(Role::Member)),
        ),
        (
            "billing",
            who(&t, AuthMethod::JwtBearer, Some(Role::Billing)),
        ),
        ("unrecognised role", who(&t, AuthMethod::JwtBearer, None)),
        ("mtls", who(&t, AuthMethod::Mtls, None)),
    ] {
        let (status, bytes) = export(&pool, claims, "").await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "{label}: {}",
            String::from_utf8_lossy(&bytes)
        );
        let body = json_of(&bytes);
        assert_eq!(body["error"], "role_forbidden", "{label}");
        assert_eq!(body["capability"], "manage_config", "{label}");
        assert!(
            body.get("sections").is_none(),
            "{label}: a refusal carries no document"
        );
    }
    // The two principals that DO hold it.
    for claims in [admin(&t), who(&t, AuthMethod::SelfHostMasterKey, None)] {
        let (status, bytes) = export(&pool, claims, "").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "{}",
            String::from_utf8_lossy(&bytes)
        );
    }
}

#[tokio::test]
#[ignore = "needs POSTGRES_TEST_URL — run with it set, filter config_routes_pg_tests"]
async fn config_export_rejects_unknown_section() {
    let pool = setup().await;
    let c = pool.get().await.unwrap();
    let t = tenant(&c, "unknown").await;
    seed(&c, &t, "u", false).await;

    for query in [
        "?sections=blocks,not_a_section",
        "?sections=",
        "?sections=blocks,,projects",
        "?sections=Blocks",
    ] {
        let (status, bytes) = export(&pool, admin(&t), query).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "{query}: {}",
            String::from_utf8_lossy(&bytes)
        );
        let body = json_of(&bytes);
        assert_eq!(body["error"], "unknown_section", "{query}");
        assert!(body.get("sections").is_none(), "{query}: nothing exported");
    }
}

#[tokio::test]
#[ignore = "needs POSTGRES_TEST_URL — run with it set, filter config_routes_pg_tests"]
async fn config_export_fails_whole_on_section_error() {
    let pool = setup().await;
    let c = pool.get().await.unwrap();
    let t = tenant(&c, "fail").await;
    seed(&c, &t, "f", false).await;
    let (status, _) = export(&pool, admin(&t), "").await;
    assert_eq!(status, StatusCode::OK, "the control run is healthy");

    // One section's store becomes unreadable; the other eleven still read fine.
    c.batch_execute("ALTER TABLE mcp_tool_rules RENAME TO mcp_tool_rules_gone")
        .await
        .unwrap();
    let (status, bytes) = export(&pool, admin(&t), "").await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        String::from_utf8_lossy(&bytes)
    );
    let body = json_of(&bytes);
    assert_eq!(body["error"], "config_export_unavailable");
    assert!(
        body.get("sections").is_none() && body.get("version").is_none(),
        "no partial document"
    );
    assert!(
        !contains(&bytes, "f-alpha"),
        "no section leaked into the refusal"
    );
    // Asking only for sections that still read succeeds: the failure is the section's, not the route's.
    let (status, _) = export(&pool, admin(&t), "?sections=blocks,projects").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
#[ignore = "requires real local Postgres"]
async fn config_export_includes_aliases_beyond_list_bound() {
    let pool = setup().await;
    let c = pool.get().await.unwrap();
    let a = tenant(&c, "many_aliases").await;
    let b = tenant(&c, "other_aliases").await;
    c.execute(
        "INSERT INTO model_aliases (tenant_id, alias, target_model, updated_by) \
         SELECT $1, 'alias-' || lpad(n::text, 4, '0'), 'fixture-model', 'fixture' \
         FROM generate_series(1, 1001) AS n",
        &[a.as_uuid()],
    )
    .await
    .unwrap();
    c.execute("INSERT INTO model_aliases (tenant_id, alias, target_model, updated_by) VALUES ($1, 'other', 'fixture-model', 'fixture')", &[b.as_uuid()]).await.unwrap();
    let (status, bytes) = export(&pool, admin(&a), "?sections=model_aliases").await;
    assert_eq!(status, StatusCode::OK);
    let doc = json_of(&bytes);
    let aliases = doc["sections"]["model_aliases"].as_array().unwrap();
    assert_eq!(
        aliases.len(),
        1001,
        "export must not truncate the stored configuration"
    );
    assert_eq!(aliases[0]["alias"], "alias-0001");
    assert_eq!(aliases[1000]["alias"], "alias-1001");
    assert!(aliases.iter().all(|a| a["alias"] != "other"));
    // The ordinary listing contract stays bounded; only canonical export is exhaustive.
    assert_eq!(
        crate::db::model_aliases::list(&pool, &a)
            .await
            .unwrap()
            .len(),
        1000
    );
}

#[tokio::test]
#[ignore = "requires real local Postgres"]
async fn config_export_keeps_one_snapshot_during_concurrent_commit() {
    let pool = setup().await;
    let mut writer = pool.get().await.unwrap();
    let t = tenant(&writer, "snapshot").await;
    writer.execute("INSERT INTO workspace_controls (tenant_id, policy, updated_by) VALUES ($1, $2, 'fixture')", &[t.as_uuid(), &json!({"generation": "before"})]).await.unwrap();
    let tx = writer.transaction().await.unwrap();
    tx.batch_execute("LOCK TABLE model_aliases IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    tx.execute(
        "UPDATE workspace_controls SET policy = $2 WHERE tenant_id = $1",
        &[t.as_uuid(), &json!({"generation": "after"})],
    )
    .await
    .unwrap();
    tx.execute("INSERT INTO model_aliases (tenant_id, alias, target_model, updated_by) VALUES ($1, 'new-alias', 'fixture-model', 'fixture')", &[t.as_uuid()]).await.unwrap();
    let reader_pool = pool.clone();
    let reader_tenant = t.clone();
    let task = tokio::spawn(async move {
        let sections = [
            crate::config_sections::find("workspace_policy").unwrap(),
            crate::config_sections::find("model_aliases").unwrap(),
        ];
        crate::config_sections::export_sections(&reader_pool, &reader_tenant, &sections)
            .await
            .unwrap()
    });
    let observer = pool.get().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let blocked: bool = observer.query_one(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid() AND wait_event_type = 'Lock' AND query LIKE '%FROM model_aliases%')", &[]
            ).await.unwrap().get(0);
            if blocked { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("export reached its second section while the writer holds the alias lock");
    tx.commit().await.unwrap();
    let parts = tokio::time::timeout(std::time::Duration::from_secs(10), task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(parts[0].1.value["policy"]["generation"], "before");
    assert_eq!(
        parts[1].1.value,
        json!([]),
        "every section must use the same pre-commit snapshot"
    );
    let (status, bytes) =
        export(&pool, admin(&t), "?sections=workspace_policy,model_aliases").await;
    assert_eq!(status, StatusCode::OK);
    let doc = json_of(&bytes);
    assert_eq!(
        doc["sections"]["workspace_policy"]["policy"]["generation"],
        "after"
    );
    assert_eq!(doc["sections"]["model_aliases"][0]["alias"], "new-alias");
}

#[tokio::test]
#[ignore = "requires real local Postgres"]
async fn config_alias_resolution_follows_policy_cap() {
    let pool = setup().await;
    let c = pool.get().await.unwrap();
    let t = tenant(&c, "alias_policy").await;
    c.execute("INSERT INTO billing_policy (key, value) VALUES ('model_aliases_max_per_workspace', '1001'::jsonb) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", &[]).await.unwrap();
    assert_eq!(
        crate::db::model_aliases::read_cap(&pool).await.unwrap(),
        Some(1001)
    );
    c.execute("INSERT INTO model_aliases (tenant_id, alias, target_model, updated_by) SELECT $1, 'model-' || n::text, 'fixture-model', 'fixture' FROM generate_series(1, 1001) AS n", &[t.as_uuid()]).await.unwrap();
    assert_eq!(
        crate::db::model_aliases::list(&pool, &t)
            .await
            .unwrap()
            .len(),
        1001,
        "resolution must support the configured cap"
    );
}

#[tokio::test]
#[ignore = "requires real local Postgres"]
async fn config_route_writer_observes_tenant_transaction_lock() {
    let pool = setup().await;
    let mut holder = pool.get().await.unwrap();
    let t = tenant(&holder, "lock").await;
    let other = tenant(&holder, "other").await;
    let tx = holder.transaction().await.unwrap();
    tx.execute(
        "SELECT pg_advisory_xact_lock(hashtextextended('config:' || $1::uuid::text, 0))",
        &[t.as_uuid()],
    )
    .await
    .unwrap();
    let actor = "fixture";
    let change = crate::db::controls::Change::Policy(Some(json!({"fixture": true})));
    // A different tenant must remain independent of the held tenant lock.
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        crate::db::controls::apply(&pool, &other, &change, actor),
    )
    .await
    .unwrap()
    .unwrap();
    let writer_pool = pool.clone();
    let writer_tenant = t.clone();
    let task = tokio::spawn(async move {
        crate::db::controls::apply(&writer_pool, &writer_tenant, &change, actor).await
    });
    let observer = pool.get().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            assert!(!task.is_finished(), "ordinary writer bypassed the config transaction lock");
            let waiting: bool = observer.query_one("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname = current_database() AND wait_event = 'advisory')", &[]).await.unwrap().get(0);
            if waiting { break; }
            tokio::task::yield_now().await;
        }
    }).await.expect("writer reached the shared lock");
    tx.rollback().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let counts: i64 = observer.query_one("SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id = $1 AND action = 'workspace.policy.update'", &[t.as_uuid()]).await.unwrap().get(0);
    assert_eq!(counts, 1);
}

#[tokio::test]
#[ignore = "requires real local Postgres"]
async fn config_shared_writes_commit_or_roll_back_with_their_audit() {
    use crate::db::{controls, model_aliases, workspace_failover};
    let pool = setup().await;
    let mut c = pool.get().await.unwrap();
    let t = tenant(&c, "atomic").await;
    let other = tenant(&c, "unaffected").await;
    let actor = crate::db::control_audit::Actor::system("fixture");
    for commit in [false, true] {
        let tx = c.transaction().await.unwrap();
        controls::apply_in_tx(
            &tx,
            &t,
            &controls::Change::Policy(Some(json!({"fixture": true}))),
            "fixture",
        )
        .await
        .unwrap();
        model_aliases::put_in_tx(&tx, &t, "friendly", "fixture-model", &actor, 10, true)
            .await
            .unwrap();
        workspace_failover::put_in_tx(
            &tx,
            &t,
            &workspace_failover::WorkspaceFailover {
                enabled: true,
                models: vec!["fixture-model".into()],
            },
            &actor,
        )
        .await
        .unwrap();
        let inside: i64 = tx
            .query_one(
                "SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id = $1",
                &[t.as_uuid()],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(inside, 3);
        if commit {
            tx.commit().await.unwrap();
        } else {
            tx.rollback().await.unwrap();
        }
        for (table, tenant_column) in [
            ("workspace_controls", "tenant_id"),
            ("model_aliases", "tenant_id"),
            ("workspace_failover", "tenant_id"),
            ("admin_audit_log", "actor_workspace_id"),
        ] {
            // Table names are a fixed test-only list; values remain bound.
            let sql = format!("SELECT count(*) FROM {table} WHERE {tenant_column} = $1");
            let count: i64 = c.query_one(&sql, &[t.as_uuid()]).await.unwrap().get(0);
            assert_eq!(
                count,
                if commit {
                    if table == "admin_audit_log" { 3 } else { 1 }
                } else {
                    0
                }
            );
            let unaffected: i64 = c.query_one(&sql, &[other.as_uuid()]).await.unwrap().get(0);
            assert_eq!(unaffected, 0);
        }
    }
}

#[tokio::test]
#[ignore = "requires real local Postgres"]
async fn config_shared_capture_noop_preserves_absence_on_commit() {
    let pool = setup().await;
    let mut c = pool.get().await.unwrap();
    let t = tenant(&c, "capture_noop").await;
    let actor = crate::db::control_audit::Actor::system("fixture");
    let tx = c.transaction().await.unwrap();
    let result = crate::db::workspace_capture::set_in_tx(&tx, &t, Default::default(), &actor)
        .await
        .unwrap();
    assert!(!result.changed);
    tx.commit().await.unwrap();
    let count: i64 = c
        .query_one(
            "SELECT count(*) FROM workspace_content_capture WHERE tenant_id = $1",
            &[t.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(count, 0);
    let audit: i64 = c
        .query_one(
            "SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id = $1",
            &[t.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(audit, 0);
}

#[tokio::test]
#[ignore = "requires real local Postgres"]
async fn config_shared_audit_refusal_rolls_back_prior_section() {
    let pool = setup().await;
    let mut c = pool.get().await.unwrap();
    let t = tenant(&c, "audit_refusal").await;
    c.batch_execute("CREATE FUNCTION fixture_refuse_alias_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = 'model_alias.put' THEN RAISE EXCEPTION 'synthetic audit refusal'; END IF; RETURN NEW; END $$; CREATE TRIGGER fixture_refuse_alias BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION fixture_refuse_alias_audit();").await.unwrap();
    let actor = crate::db::control_audit::Actor::system("fixture");
    let tx = c.transaction().await.unwrap();
    crate::db::controls::apply_in_tx(
        &tx,
        &t,
        &crate::db::controls::Change::Policy(Some(json!({"fixture": true}))),
        "fixture",
    )
    .await
    .unwrap();
    assert!(
        crate::db::model_aliases::put_in_tx(&tx, &t, "friendly", "fixture-model", &actor, 10, true)
            .await
            .is_err()
    );
    tx.rollback().await.unwrap();
    for sql in [
        "SELECT count(*) FROM workspace_controls WHERE tenant_id = $1",
        "SELECT count(*) FROM model_aliases WHERE tenant_id = $1",
        "SELECT count(*) FROM admin_audit_log WHERE actor_workspace_id = $1",
    ] {
        let count: i64 = c.query_one(sql, &[t.as_uuid()]).await.unwrap().get(0);
        assert_eq!(count, 0);
    }
}

#[tokio::test]
#[ignore = "requires real local Postgres"]
async fn config_alias_resolution_preserves_reads_when_cap_drops_or_is_unavailable() {
    let pool = setup().await;
    let c = pool.get().await.unwrap();
    let t = tenant(&c, "alias_existing").await;
    c.execute("INSERT INTO model_aliases (tenant_id, alias, target_model, updated_by) SELECT $1, 'model-' || n::text, 'fixture-model', 'fixture' FROM generate_series(1, 2) AS n", &[t.as_uuid()]).await.unwrap();
    for value in [json!(1), json!("invalid")] {
        c.execute("INSERT INTO billing_policy (key, value) VALUES ('model_aliases_max_per_workspace', $1) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value", &[&value]).await.unwrap();
        assert_eq!(
            crate::db::model_aliases::list(&pool, &t)
                .await
                .unwrap()
                .len(),
            2
        );
    }
    c.execute(
        "DELETE FROM billing_policy WHERE key = 'model_aliases_max_per_workspace'",
        &[],
    )
    .await
    .unwrap();
    assert_eq!(
        crate::db::model_aliases::read_cap(&pool).await.unwrap(),
        None
    );
    assert_eq!(
        crate::db::model_aliases::list(&pool, &t)
            .await
            .unwrap()
            .len(),
        2
    );
}

/// Review of #382 (Medium): a duplicate project name inside a shared transaction is a
/// per-item refusal. Without a savepoint Postgres aborts the whole transaction, and a caller
/// that reports `NameTaken` and commits would silently roll back every other section.
#[tokio::test]
#[ignore = "requires real local Postgres"]
async fn config_shared_project_name_collision_keeps_the_rest_of_the_transaction() {
    use crate::db::{controls, projects};
    let pool = setup().await;
    let mut c = pool.get().await.unwrap();
    let t = tenant(&c, "collision").await;
    let actor = crate::db::control_audit::Actor::system("fixture");
    let project = projects::NewProject {
        name: "fixture-project".into(),
        environments: vec!["prod".into()],
        policy: None,
    };
    {
        let tx = c.transaction().await.unwrap();
        let first = projects::create_in_tx(&tx, &t, &project, 10, &actor)
            .await
            .unwrap();
        assert!(matches!(first, projects::CreateOutcome::Created(_)));
        tx.commit().await.unwrap();
    }
    let tx = c.transaction().await.unwrap();
    controls::apply_in_tx(
        &tx,
        &t,
        &controls::Change::Policy(Some(json!({"fixture": "kept"}))),
        "fixture",
    )
    .await
    .unwrap();
    let dup = projects::create_in_tx(&tx, &t, &project, 10, &actor)
        .await
        .unwrap();
    assert!(matches!(dup, projects::CreateOutcome::NameTaken));
    tx.commit().await.unwrap();
    let kept: i64 = c
        .query_one(
            "SELECT count(*) FROM workspace_controls WHERE tenant_id = $1",
            &[t.as_uuid()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(kept, 1, "the other section survived the name collision");
}

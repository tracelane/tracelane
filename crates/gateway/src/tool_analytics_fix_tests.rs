use super::*;
use axum::{body::Body, http::Request};
use serde_json::{Value, json};
use std::sync::Arc;
use tower::ServiceExt;

/// Uses only a disposable loopback service. Random tenants isolate these cases
/// from each other and from the existing ClickHouse integration test family.
async fn clickhouse() -> clickhouse::Client {
    let url = std::env::var("CLICKHOUSE_TEST_URL").expect("set disposable CLICKHOUSE_TEST_URL");
    assert_eq!(
        url, "http://127.0.0.1:18138",
        "disposable FIX ClickHouse only"
    );
    let server = clickhouse::Client::default().with_url(url);
    server
        .query("CREATE DATABASE IF NOT EXISTS tracelane")
        .execute()
        .await
        .unwrap();
    let ch = server.with_database("tracelane");
    // Other retention proofs install a minimal spans table on this disposable service.
    ch.query("DROP TABLE IF EXISTS tracelane.spans")
        .execute()
        .await
        .unwrap();
    let schema = include_str!("../../../infra/dev/clickhouse/schema.sql");
    let statement = crate::clickhouse_query::split_migration_statements(schema)
        .into_iter()
        .find(|s| s.contains("CREATE TABLE IF NOT EXISTS tracelane.spans\n"))
        .expect("checked-in spans DDL");
    ch.query(&statement)
        .execute()
        .await
        .expect("checked-in spans schema applies");
    ch
}

fn claims() -> crate::auth::Claims {
    crate::auth::Claims {
        tenant_id: tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::new_v4()),
        ..crate::auth::dev_stub_claims(crate::auth::AuthMethod::JwtBearer)
    }
}

fn state(ch: &clickhouse::Client, days: i32) -> ToolAnalyticsState {
    ToolAnalyticsState {
        ch: ch.clone(),
        entitlements: Some(Arc::new(crate::entitlement_cache::EntitlementCache::new(
            Arc::new(move |_| {
                Box::pin(async move {
                    Ok(crate::entitlement_cache::ResolvedEntitlements {
                        queryable_days: days,
                        ..crate::entitlement_cache::ResolvedEntitlements::deny_all()
                    })
                })
            }),
        ))),
    }
}

fn attributes(method: &str, tool: &str) -> Value {
    json!({
        "mcp.method.name": method,
        "gen_ai.tool.name": tool,
        "tracelane.mcp.server": format!("server-{tool}"),
        "tracelane_api_key_id": format!("key-{tool}")
    })
}

async fn insert(
    ch: &clickhouse::Client,
    caller: &crate::auth::Claims,
    count: u32,
    at: i64,
    duration_ms: u32,
    attributes: Value,
) {
    let status = if attributes.get("error_type").is_some() {
        2_u8
    } else {
        1_u8
    };
    let intervention = if attributes["tracelane_intervention"] == "block" {
        2_u8
    } else {
        0_u8
    };
    ch.query(
        "INSERT INTO tracelane.spans (tenant_id,trace_id,span_id,name,start_time,end_time,status_code,attributes,intervention) \
         SELECT ?,toString(generateUUIDv4()),toString(generateUUIDv4()),'mcp test',toDateTime(?), \
         toDateTime(?) + toIntervalMillisecond(?),?,?,? FROM numbers(?)",
    )
    .bind(caller.tenant_id.to_string())
    .bind(at).bind(at).bind(duration_ms).bind(status)
    .bind(attributes.to_string()).bind(intervention).bind(count)
    .execute().await.expect("insert real MCP spans");
}

async fn usage(
    state: ToolAnalyticsState,
    caller: &crate::auth::Claims,
    group: &str,
    since: i64,
    until: i64,
) -> (StatusCode, Value) {
    let timestamp = |t| {
        chrono::DateTime::from_timestamp(t, 0)
            .unwrap()
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    };
    let _auth = crate::auth::test_claims::Guard::set(caller.clone());
    let request = Request::builder()
        .uri(format!(
            "/v1/mcp-usage?group_by={group}&since={}&until={}",
            timestamp(since),
            timestamp(until)
        ))
        .header("authorization", "Bearer fixture")
        .body(Body::empty())
        .unwrap();
    let response = routes().with_state(state).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|_| json!({"text":String::from_utf8_lossy(&bytes)}));
    (status, value)
}

#[tokio::test]
#[ignore = "requires disposable CLICKHOUSE_TEST_URL; real ClickHouse handler proof"]
async fn mcp_usage_counts_every_canonical_block_and_excludes_tool_errors() {
    let ch = clickhouse().await;
    let caller = claims();
    let now = chrono::Utc::now().timestamp();
    for reason in [
        "mcp_tool_denied",
        "mcp_tool_definition_changed",
        "mcp_tool_unverifiable",
        "approval_required",
        "approval_denied",
        "approval_expired",
        "approval_consumed",
        "mcp_tool_error",
    ] {
        let mut attrs = attributes("tools/call", reason);
        attrs["error_type"] = json!(reason);
        attrs["tracelane_intervention"] = json!("block");
        insert(&ch, &caller, 1, now - 10, 10, attrs).await;
    }
    let mut ordinary_error = attributes("tools/call", "ordinary-tool-error");
    ordinary_error["error_type"] = json!("mcp_tool_error");
    insert(&ch, &caller, 1, now - 10, 10, ordinary_error).await;
    let (status, body) = usage(state(&ch, 30), &caller, "tool", now - 3600, now).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = body["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 9);
    for row in rows {
        assert_eq!(row["calls"], 1);
        assert_eq!(row["errors"], 1);
        let blocked = row["dimension"] != "ordinary-tool-error";
        assert_eq!(row["refused"], u64::from(blocked), "{row}");
        assert_eq!(row["would_block"], 0);
    }
}

#[tokio::test]
#[ignore = "requires disposable CLICKHOUSE_TEST_URL; real ClickHouse handler proof"]
async fn mcp_usage_preserves_multiple_observe_verdicts() {
    let ch = clickhouse().await;
    let caller = claims();
    let now = chrono::Utc::now().timestamp();
    let mut attrs = attributes("tools/call", "read");
    attrs["tracelane.mcp.verdicts"] = json!([
        {"check":"rule","mode":"observe","outcome":"would_deny","reason_code":"would_deny"},
        {"check":"pin","mode":"observe","outcome":"pin_unverified","reason_code":"pin_unverified"}
    ]);
    attrs["tracelane.mcp.verdict"] = json!("pin_unverified");
    insert(&ch, &caller, 1, now - 10, 10, attrs).await;
    let (status, body) = usage(state(&ch, 30), &caller, "total", now - 3600, now).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = body["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["calls"], 1);
    assert_eq!(
        rows[0]["would_block"], 1,
        "a later verdict cannot erase an observed denial"
    );
    assert_eq!(rows[0]["refused"], 0);
}

#[tokio::test]
#[ignore = "requires disposable CLICKHOUSE_TEST_URL; real ClickHouse handler proof"]
async fn mcp_usage_reports_group_truncation() {
    let ch = clickhouse().await;
    let caller = claims();
    let now = chrono::Utc::now().timestamp();
    let max = crate::mcp_policy::settings()
        .unwrap()
        .spans
        .usage
        .max_groups;
    for i in 0..=max {
        insert(
            &ch,
            &caller,
            1,
            now - 10,
            10,
            attributes("tools/call", &format!("tool-{i}")),
        )
        .await;
    }
    let (status, body) = usage(state(&ch, 30), &caller, "tool", now - 3600, now).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rows"].as_array().unwrap().len(), max as usize);
    assert_eq!(body["partial"], true, "LIMIT must disclose missing groups");
    assert!(
        body["total_calls"].as_u64() == Some(u64::from(max) + 1)
            || body["group_count"].as_u64() == Some(u64::from(max) + 1),
        "a capped breakdown must report the true total: {body}"
    );
}

#[tokio::test]
#[ignore = "requires disposable CLICKHOUSE_TEST_URL; real ClickHouse handler proof"]
async fn mcp_usage_p95_excludes_ping_and_initialize() {
    let ch = clickhouse().await;
    let caller = claims();
    let now = chrono::Utc::now().timestamp();
    let min = crate::mcp_policy::settings()
        .unwrap()
        .spans
        .usage
        .min_samples_for_p95;
    assert!(min > 1);
    for method in ["ping", "initialize"] {
        insert(
            &ch,
            &caller,
            min,
            now - 10,
            60_000,
            attributes(method, "setup"),
        )
        .await;
    }
    let (status, body) = usage(state(&ch, 30), &caller, "total", now - 3600, now).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rows"][0]["calls"], u64::from(min) * 2);
    assert!(
        body["rows"][0]["p95_ms"].is_null(),
        "setup traffic is not a latency sample: {body}"
    );
    insert(
        &ch,
        &caller,
        min - 1,
        now - 10,
        10,
        attributes("tools/call", "read"),
    )
    .await;
    let (status, body) = usage(state(&ch, 30), &caller, "total", now - 3600, now).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rows"][0]["calls"], u64::from(min) * 3 - 1);
    assert!(
        body["rows"][0]["p95_ms"].is_null(),
        "only eligible samples count toward the threshold"
    );
    insert(
        &ch,
        &caller,
        1,
        now - 10,
        10,
        attributes("tools/call", "read"),
    )
    .await;
    let (status, body) = usage(state(&ch, 30), &caller, "total", now - 3600, now).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["rows"][0]["calls"], u64::from(min) * 3);
    let p95 = body["rows"][0]["p95_ms"]
        .as_f64()
        .expect("enough eligible latency samples");
    assert!(
        (p95 - 10.0).abs() < 0.01,
        "setup latency contaminated p95: {p95}"
    );
}

#[tokio::test]
#[ignore = "requires disposable CLICKHOUSE_TEST_URL; real ClickHouse handler proof"]
async fn mcp_usage_all_groupings_are_tenant_scoped_and_window_bounded() {
    let ch = clickhouse().await;
    let alice = claims();
    let bob = claims();
    let now = chrono::Utc::now().timestamp();
    insert(
        &ch,
        &alice,
        2,
        now - 60,
        10,
        attributes("tools/call", "alice-visible"),
    )
    .await;
    insert(
        &ch,
        &alice,
        4,
        now - 7200,
        10,
        attributes("tools/call", "before-window"),
    )
    .await;
    insert(
        &ch,
        &alice,
        8,
        now - 5,
        10,
        attributes("tools/call", "after-window"),
    )
    .await;
    insert(
        &ch,
        &bob,
        16,
        now - 60,
        10,
        attributes("tools/call", "bob-secret"),
    )
    .await;
    for group in ["total", "server", "tool", "key"] {
        let (status, body) = usage(state(&ch, 30), &alice, group, now - 3600, now - 10).await;
        assert_eq!(status, StatusCode::OK, "{group}: {body}");
        assert_eq!(body["rows"].as_array().unwrap().len(), 1, "{group}: {body}");
        assert_eq!(body["rows"][0]["calls"], 2, "{group}: {body}");
        assert!(body["rows"][0]["p95_ms"].is_null());
        let serialized = body.to_string();
        for hidden in ["bob-secret", "before-window", "after-window"] {
            assert!(!serialized.contains(hidden), "{group} exposed {hidden}");
        }
        let (status, body) = usage(state(&ch, 30), &bob, group, now - 3600, now - 10).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["rows"][0]["calls"], 16);
        assert!(!body.to_string().contains("alice-visible"));
    }
}

#[tokio::test]
#[ignore = "requires disposable CLICKHOUSE_TEST_URL; real ClickHouse handler proof"]
async fn mcp_usage_retention_hides_old_spans_before_physical_deletion() {
    let ch = clickhouse().await;
    let caller = claims();
    let now = chrono::Utc::now().timestamp();
    let days = 7;
    insert(
        &ch,
        &caller,
        1,
        now - 60,
        10,
        attributes("tools/call", "visible-new"),
    )
    .await;
    insert(
        &ch,
        &caller,
        2,
        now - i64::from(days + 1) * 86400,
        10,
        attributes("tools/call", "private-old"),
    )
    .await;
    let physical = ch
        .query("SELECT count() FROM tracelane.spans WHERE tenant_id = ?")
        .bind(caller.tenant_id.to_string())
        .fetch_one::<u64>()
        .await
        .unwrap();
    assert_eq!(
        physical, 3,
        "old data is physically present before the read"
    );
    for group in ["total", "server", "tool", "key"] {
        let (status, body) = usage(state(&ch, days), &caller, group, now - 14 * 86400, now).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["rows"].as_array().unwrap().len(), 1);
        assert_eq!(body["rows"][0]["calls"], 1);
        assert!(!body.to_string().contains("private-old"));
    }
}

#[tokio::test]
async fn mcp_usage_rejects_overwide_reversed_and_future_windows_before_query() {
    let caller = claims();
    let now = chrono::Utc::now().timestamp();
    let max = i64::from(
        crate::mcp_policy::settings()
            .unwrap()
            .spans
            .usage
            .window_max_days,
    ) * 86400;
    for (since, until) in [(now - max - 1, now), (now, now - 1), (now - 60, now + 3600)] {
        let (status, body) = usage(
            state(&clickhouse::Client::default(), 30),
            &caller,
            "total",
            since,
            until,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "window_too_large");
    }
}

#[tokio::test]
async fn mcp_usage_invalid_window_has_gateway_error_shape() {
    let caller = claims();
    let now = chrono::Utc::now().timestamp();
    let (status, body) = usage(
        state(&clickhouse::Client::default(), 30),
        &caller,
        "total",
        now,
        now - 1,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "window_too_large");
    assert_eq!(body["message"], "window too large");
}

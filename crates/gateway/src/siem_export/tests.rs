use super::*;
use serde_json::json;
use tracelane_shared::{
    TenantId,
    span::{SpanAttributes, SpanStatus},
};
fn tenant() -> Uuid {
    Uuid::from_u128(1)
}
fn span() -> TracelaneSpan {
    TracelaneSpan {
        span_id: Uuid::from_u128(2),
        trace_id: Uuid::from_u128(3),
        parent_span_id: None,
        tenant_id: TenantId::from_jwt_claim(tenant()),
        name: "chat test-model".into(),
        start_time: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        end_time: None,
        status: SpanStatus::default(),
        attributes: SpanAttributes {
            gen_ai_operation_name: Some("chat".into()),
            gen_ai_provider_name: Some("openai".into()),
            gen_ai_request_model: Some("test-model".into()),
            gen_ai_usage_input_tokens: Some(7),
            gen_ai_usage_output_tokens: Some(9),
            ..Default::default()
        },
    }
}
fn action(event: Value) -> Envelope {
    serde_json::from_value(json!({"schema_version":1,"tenant_id":tenant(),"event_id":Uuid::from_u128(4),"action_id":Uuid::from_u128(5),"agent_key_id":null,"occurred_at":"2023-11-14T22:13:20Z","request_digest":"synthetic-digest","body":event})).unwrap()
}
fn record() -> Record {
    Record {
        tenant: tenant(),
        id: Uuid::from_u128(2),
        time: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        event: "span".into(),
        attributes: json!({"gen_ai.operation.name":"chat"}),
    }
}
#[test]
fn obs64_span_mapping() {
    let r = span_record(&span()).unwrap();
    assert_eq!(r.tenant, tenant());
    assert_ne!(r.id, Uuid::from_u128(2));
    assert_eq!(
        r.attributes,
        json!({"gen_ai.operation.name":"chat","gen_ai.provider.name":"openai","gen_ai.request.model":"test-model","gen_ai.usage.input_tokens":7,"gen_ai.usage.output_tokens":9,"tracelane.trace_id":Uuid::from_u128(3)})
    );
}
#[test]
fn obs64_action_execution_mapping() {
    let a = action(
        json!({"event_type":"execution_started","execution_id":Uuid::from_u128(6),"idempotency_key":Uuid::from_u128(7),"attestation_key_id":"public-id"}),
    );
    let r = action_record(tenant(), &a).unwrap();
    assert_eq!(r.event, "execution_started");
    assert_eq!(r.attributes["gen_ai.operation.name"], "execute_tool");
    assert_eq!(r.attributes["tracelane.action_id"], json!(a.action_id));
}
#[test]
fn obs64_action_decision_mapping() {
    let a = action(
        json!({"event_type":"decision_made","decision":"deny","rule_id":"synthetic-rule","reason_codes":["policy_denied"],"policy_id":Uuid::from_u128(8),"policy_version":1,"policy_hash":"digest"}),
    );
    let r = action_record(tenant(), &a).unwrap();
    assert!(r.attributes.get("gen_ai.operation.name").is_none());
    assert_eq!(r.attributes["tracelane.decision"], "deny");
    assert_eq!(
        r.attributes["tracelane.reason_codes"],
        json!(["policy_denied"])
    );
}
#[test]
fn obs64_splunk_payload() {
    assert_eq!(
        payload(Connector::Splunk, &record()).unwrap(),
        json!({"time":1700000000.0,"source":"tracelane","sourcetype":"tracelane:genai","event":{"id":Uuid::from_u128(2),"tenant_id":tenant(),"event":"span","schema_url":"https://opentelemetry.io/schemas/1.41.1","attributes":{"gen_ai.operation.name":"chat"}}})
    );
}
#[test]
fn obs64_sentinel_payload() {
    assert_eq!(
        payload(Connector::Sentinel, &record()).unwrap(),
        json!([{"TimeGenerated":"2023-11-14T22:13:20+00:00","RecordId":Uuid::from_u128(2),"TenantId":tenant(),"Event":"span","SchemaUrl":"https://opentelemetry.io/schemas/1.41.1","Attributes":{"gen_ai.operation.name":"chat"}}])
    );
}
#[test]
fn obs64_ocsf_payload() {
    let p = payload(Connector::Ocsf, &record()).unwrap();
    assert_eq!(
        p,
        json!({"class_uid":6003,"category_uid":6,"activity_id":99,"type_uid":600399,"severity_id":1,"time":1700000000000_i64,"metadata":{"version":"1.4.0","product":{"name":"Tracelane","vendor_name":"Tracelane"},"uid":Uuid::from_u128(2)},"actor":{"app_name":"Tracelane evidence exporter"},"api":{"operation":"span"},"unmapped":{"tenant_id":tenant(),"schema_url":"https://opentelemetry.io/schemas/1.41.1","attributes":{"gen_ai.operation.name":"chat"}}})
    );
}
#[test]
fn obs64_semconv_keys() {
    let reference: Value =
        serde_json::from_str(include_str!("fixtures/semconv-v1.41.1.json")).unwrap();
    assert_eq!(reference["attributes"].as_array().unwrap().len(), 50);
    let r = span_record(&span()).unwrap();
    for field in SPAN_FIELDS {
        let key = tracelane_shared::otlp::encode::semconv_key(field).unwrap();
        assert!(
            reference["attributes"]
                .as_array()
                .unwrap()
                .contains(&json!(key)),
            "{key}"
        );
    }
    assert!(
        r.attributes
            .as_object()
            .unwrap()
            .keys()
            .filter(|k| k.starts_with("gen_ai."))
            .all(|key| reference["attributes"]
                .as_array()
                .unwrap()
                .contains(&json!(key)))
    );
}

#[test]
fn obs64_content_omitted() {
    let mut s = span();
    s.attributes.gen_ai_tool_call_arguments = Some("synthetic-private-content".into());
    s.attributes
        .extra
        .insert("untrusted".into(), json!("synthetic-private-content"));
    assert!(
        !serde_json::to_string(&span_record(&s).unwrap())
            .unwrap()
            .contains("synthetic-private-content")
    );
}
#[test]
fn obs64_cross_tenant_rejected() {
    let a = action(json!({"event_type":"denied_runtime","reason":"policy_denied"}));
    assert!(action_record(Uuid::from_u128(9), &a).is_err());
}
#[test]
fn obs64_url_userinfo_rejected() {
    assert!(
        validate_destination(
            Connector::Splunk,
            "https://fake-user:fake-pass@example.com/services/collector/event"
        )
        .is_err()
    );
}
#[test]
fn obs64_url_query_rejected() {
    assert!(
        validate_destination(
            Connector::Ocsf,
            "https://example.com/events?token=synthetic"
        )
        .is_err()
    );
}
#[test]
fn obs64_https_required() {
    assert!(validate_destination(Connector::Ocsf, "http://example.com/events").is_err());
}
#[test]
fn obs64_fragment_rejected() {
    assert!(validate_destination(Connector::Ocsf, "https://example.com/events#synthetic").is_err());
}
#[test]
fn obs64_splunk_destination() {
    assert!(
        validate_destination(
            Connector::Splunk,
            "https://example.com/services/collector/event"
        )
        .is_ok()
    );
}
#[test]
fn obs64_sentinel_destination() {
    assert!(
        validate_destination(
            Connector::Sentinel,
            "https://example.com/dataCollectionRules/dcr-synthetic/streams/Custom-Tracelane"
        )
        .is_ok()
    );
}
#[test]
fn obs64_ocsf_destination() {
    assert!(validate_destination(Connector::Ocsf, "https://example.com/events").is_ok());
}
fn config() -> DeliveryConfig {
    DeliveryConfig {
        timeout: std::time::Duration::from_millis(250),
        max_bytes: 65536,
        retry_delays: vec![std::time::Duration::from_millis(1)],
    }
}
fn destination(server: &wiremock::MockServer, kind: Connector) -> Destination {
    Destination {
        tenant: tenant(),
        id: Uuid::from_u128(10),
        kind,
        url: format!(
            "{}{}",
            server.uri(),
            match kind {
                Connector::Splunk => "/services/collector/event",
                Connector::Sentinel =>
                    "/dataCollectionRules/dcr-synthetic/streams/Custom-Tracelane",
                Connector::Ocsf => "/events",
            }
        ),
        credential: secrecy::SecretString::from("FAKEtestkeyDONOTUSE".to_owned()),
    }
}
async fn wire(kind: Connector) {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{body_json, header, method},
    };
    let server = MockServer::start().await;
    let d = destination(&server, kind);
    let expected = payload(kind, &record()).unwrap();
    Mock::given(method("POST"))
        .and(body_json(expected))
        .and(header(
            "authorization",
            match kind {
                Connector::Splunk => "Splunk FAKEtestkeyDONOTUSE",
                _ => "Bearer FAKEtestkeyDONOTUSE",
            },
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"code":0})))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(deliver(&d, &record(), &config()).await.unwrap(), 1);
}
#[tokio::test]
async fn obs64_splunk_wire_payload() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    wire(Connector::Splunk).await;
}
#[tokio::test]
async fn obs64_sentinel_wire_payload() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    wire(Connector::Sentinel).await;
}
#[tokio::test]
async fn obs64_ocsf_wire_payload() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    wire(Connector::Ocsf).await;
}
#[tokio::test]
async fn obs64_splunk_application_failure() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_json(json!({"code":4})))
        .expect(2)
        .mount(&server)
        .await;
    assert!(
        deliver(
            &destination(&server, Connector::Splunk),
            &record(),
            &config()
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn obs64_retry_exhausted() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let server = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(503))
        .expect(2)
        .mount(&server)
        .await;
    assert!(
        deliver(&destination(&server, Connector::Ocsf), &record(), &config())
            .await
            .is_err()
    );
}
#[tokio::test]
async fn obs64_retry_then_success() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let server = wiremock::MockServer::start().await;
    let n = Arc::new(AtomicUsize::new(0));
    let count = n.clone();
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(move |_: &wiremock::Request| {
            wiremock::ResponseTemplate::new(if count.fetch_add(1, Ordering::SeqCst) == 0 {
                503
            } else {
                200
            })
        })
        .expect(2)
        .mount(&server)
        .await;
    assert_eq!(
        deliver(&destination(&server, Connector::Ocsf), &record(), &config())
            .await
            .unwrap(),
        2
    );
}
#[tokio::test]
async fn obs64_tenant_destination_isolation() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let a = wiremock::MockServer::start().await;
    let b = wiremock::MockServer::start().await;
    let mut wrong = destination(&b, Connector::Ocsf);
    wrong.tenant = Uuid::from_u128(99);
    assert!(deliver(&wrong, &record(), &config()).await.is_err());
    assert!(b.received_requests().await.unwrap().is_empty());
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .expect(1)
        .mount(&a)
        .await;
    deliver(&destination(&a, Connector::Ocsf), &record(), &config())
        .await
        .unwrap();
}
#[tokio::test]
async fn obs64_redirect_rejected() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let a = wiremock::MockServer::start().await;
    let b = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(307)
                .insert_header("Location", format!("{}/capture", b.uri())),
        )
        .mount(&a)
        .await;
    assert!(
        deliver(&destination(&a, Connector::Ocsf), &record(), &config())
            .await
            .is_err()
    );
    assert!(b.received_requests().await.unwrap().is_empty());
}
#[tokio::test]
async fn obs64_oversize_rejected() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let s = wiremock::MockServer::start().await;
    let mut c = config();
    c.max_bytes = 1;
    assert!(
        deliver(&destination(&s, Connector::Ocsf), &record(), &c)
            .await
            .is_err()
    );
    assert!(s.received_requests().await.unwrap().is_empty());
}
#[tokio::test]
async fn obs64_timeout_bounded() {
    let _ssrf = crate::handler_harness::LoopbackBypassGuard::new();
    let s = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("POST"))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_delay(std::time::Duration::from_secs(10)),
        )
        .mount(&s)
        .await;
    let mut c = config();
    c.timeout = std::time::Duration::from_millis(10);
    c.retry_delays.clear();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        deliver(&destination(&s, Connector::Ocsf), &record(), &c),
    )
    .await;
    assert!(result.is_ok());
    assert!(result.unwrap().is_err());
}

fn span_wire(t: Uuid) -> Vec<u8> {
    span_wire_trace(t, Uuid::from_u128(3))
}
fn span_wire_trace(t: Uuid, trace: Uuid) -> Vec<u8> {
    fn string(out: &mut Vec<u8>, text: &str) {
        let mut n = text.len();
        while n >= 128 {
            out.push((n as u8) | 128);
            n >>= 7;
        }
        out.push(n as u8);
        out.extend_from_slice(text.as_bytes());
    }
    let mut out = Vec::new();
    for s in [
        t.to_string(),
        Uuid::from_u128(2).to_string(),
        trace.to_string(),
    ] {
        string(&mut out, &s);
    }
    out.extend_from_slice(&1_700_000_000_000_000_i64.to_le_bytes());
    string(
        &mut out,
        r#"{"gen_ai_operation_name":"chat","gen_ai_request_model":"test-model","prompt":"DO_NOT_EXPORT"}"#,
    );
    out.extend_from_slice(&1_700_000_000_000_i64.to_le_bytes());
    out
}
#[tokio::test]
async fn obs64_source_span() {
    let mock = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200).set_body_bytes(span_wire(tenant())))
        .mount(&mock)
        .await;
    let ch = clickhouse::Client::default()
        .with_url(mock.uri())
        .with_compression(clickhouse::Compression::None);
    let b = worker::span_batch(
        &ch,
        tenant(),
        0,
        "",
        "",
        crate::clickhouse_query::PlanTier::Free,
        &worker::Config::default(),
    )
    .await
    .unwrap();
    assert_eq!(b.records().len(), 1);
    assert_eq!(b.cursor_ms, 1_700_000_000_000);
    assert_eq!(b.cursor_id, Uuid::from_u128(2).to_string());
    assert_eq!(
        b.records()[0].attributes,
        json!({"gen_ai.operation.name":"chat","gen_ai.request.model":"test-model","tracelane.trace_id":Uuid::from_u128(3)})
    );
}
#[tokio::test]
async fn obs64_source_tenant_mismatch() {
    let mock = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .respond_with(
            wiremock::ResponseTemplate::new(200).set_body_bytes(span_wire(Uuid::new_v4())),
        )
        .mount(&mock)
        .await;
    let ch = clickhouse::Client::default()
        .with_url(mock.uri())
        .with_compression(clickhouse::Compression::None);
    assert!(
        worker::span_batch(
            &ch,
            tenant(),
            0,
            "",
            "",
            crate::clickhouse_query::PlanTier::Free,
            &worker::Config::default()
        )
        .await
        .is_err()
    );
}
#[tokio::test]
async fn obs64_source_query_bounds() {
    let mock = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .respond_with(wiremock::ResponseTemplate::new(200))
        .mount(&mock)
        .await;
    let ch = clickhouse::Client::default()
        .with_url(mock.uri())
        .with_compression(clickhouse::Compression::None);
    let c = worker::Config {
        batch: 7,
        ..worker::Config::default()
    };
    worker::span_batch(
        &ch,
        tenant(),
        123,
        "last-trace",
        "last",
        crate::clickhouse_query::PlanTier::Free,
        &c,
    )
    .await
    .unwrap();
    let requests = mock.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    let sql = requests[0]
        .url
        .query_pairs()
        .find(|(k, _)| k == "query")
        .unwrap()
        .1
        .into_owned();
    assert!(sql.contains(&format!("tenant_id='{}'", tenant())), "{sql}");
    for piece in [
        "ingested_at",
        "123",
        "last",
        "LIMIT 7",
        "max_memory_usage",
        "max_execution_time",
    ] {
        assert!(sql.contains(piece), "missing {piece}: {sql}");
    }
}

#[test]
fn obs64_source_span_identity_includes_trace_and_projection() {
    let a = span();
    let mut b = a.clone();
    b.trace_id = Uuid::from_u128(99);
    assert_ne!(span_record(&a).unwrap().id, span_record(&b).unwrap().id);
    assert_eq!(span_record(&a).unwrap().id, span_record(&a).unwrap().id);
    b = a.clone();
    b.attributes.gen_ai_response_model = Some("changed-model".into());
    assert_ne!(span_record(&a).unwrap().id, span_record(&b).unwrap().id);
}

#[tokio::test]
async fn obs64_source_same_span_across_traces_batch_one() {
    let mock = wiremock::MockServer::start().await;
    wiremock::Mock::given(wiremock::matchers::method("GET"))
        .respond_with(|r: &wiremock::Request| {
            let sql = r.url.as_str();
            let trace = if sql.contains(&Uuid::from_u128(3).to_string()) {
                Uuid::from_u128(4)
            } else {
                Uuid::from_u128(3)
            };
            wiremock::ResponseTemplate::new(200).set_body_bytes(span_wire_trace(tenant(), trace))
        })
        .mount(&mock)
        .await;
    let ch = clickhouse::Client::default()
        .with_url(mock.uri())
        .with_compression(clickhouse::Compression::None);
    let c = worker::Config {
        batch: 1,
        ..worker::Config::default()
    };
    let first = worker::span_batch(
        &ch,
        tenant(),
        0,
        "",
        "",
        crate::clickhouse_query::PlanTier::Free,
        &c,
    )
    .await
    .unwrap();
    assert_eq!(first.records().len(), 1);
    let second = worker::span_batch(
        &ch,
        tenant(),
        first.cursor_ms,
        &first.cursor_trace,
        &first.cursor_id,
        crate::clickhouse_query::PlanTier::Free,
        &c,
    )
    .await
    .unwrap();
    assert_eq!(second.records().len(), 1);
    assert_eq!(first.cursor_ms, second.cursor_ms);
    assert_eq!(first.cursor_id, second.cursor_id);
    assert_ne!(first.cursor_trace, second.cursor_trace);
    assert_ne!(first.records()[0].id, second.records()[0].id);
}

#[test]
fn obs64_worker_reference_table_parses() {
    let c = worker::parse_table(include_str!("../../translation_policy.v1.json"))
        .expect("shipped siem_export block parses");
    assert!(
        c.poll.as_secs() > 300,
        "poll must exceed the Neon suspend floor"
    );
    assert!(c.batch > 0 && c.concurrency > 0);
    assert!(c.destination_budget > c.delivery.timeout);
    assert!(worker::parse_table("{}").is_none());
    // Each bound refused on its own: the shipped block with ONE field out of range.
    let shipped: Value =
        serde_json::from_str(include_str!("../../translation_policy.v1.json")).unwrap();
    for (field, bad) in [
        ("batch", json!(0)),
        ("batch", json!(10_001)),
        ("concurrency", json!(65)),
        ("destination_budget_secs", json!(u64::MAX)),
        ("poll_secs", json!(86_401)),
        ("retry_delays_secs", json!([0, u64::MAX])),
    ] {
        let mut doc = shipped.clone();
        doc["siem_export"][field] = bad.clone();
        assert!(
            worker::parse_table(&doc.to_string()).is_none(),
            "{field}={bad} must be refused"
        );
    }
}

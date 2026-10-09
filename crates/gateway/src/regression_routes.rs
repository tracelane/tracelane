//! Recorded and mocked fixtures reuse the dataset's content decoder and JSONL shape.
use crate::dataset_routes::{DatasetItem, DatasetStore, SpanContentRow, SpanVerdict};
use crate::incident_routes::IncidentState;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::sync::Arc;
type ApiError = (StatusCode, Json<Value>);
async fn claims_from_auth(headers: &HeaderMap) -> Result<crate::auth::Claims, ApiError> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| error(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    crate::auth::validate_authorization(authorization)
        .await
        .map_err(|e| error(crate::auth::failure_status(&e), "unauthorized"))
}
fn error(status: StatusCode, code: &str) -> ApiError {
    (status, Json(json!({"code":code,"error":code})))
}
const LIMITS: &str = "expected_output is null: output_not_captured. Recorded mode is inspection only. Mocked mode uses recorded tool messages as fixed context; no tools execute. Live mode is not supported. Choose assertions before running a model.";
#[derive(Clone)]
pub struct RegressionState {
    pub incident: IncidentState,
    pub datasets: Arc<dyn DatasetStore>,
    pub entitlements: Option<Arc<crate::entitlement_cache::EntitlementCache>>,
}
/// Mount recorded or mocked fixture exports; no tools execute.
/// # Errors
/// Construction is infallible; handlers fail CLOSED on auth, capture policy,
/// entitlement, rate, storage, content-decoding or serialization failures.
pub fn routes() -> Router<RegressionState> {
    Router::new().route("/v1/traces/{trace_id}/regression", get(export))
}
#[derive(Deserialize)]
struct ExportQuery {
    #[serde(default = "dataset_format")]
    format: String,
    #[serde(default = "recorded_mode")]
    mode: String,
}
fn dataset_format() -> String {
    "dataset".into()
}
fn recorded_mode() -> String {
    "recorded".into()
}
async fn export(
    State(state): State<RegressionState>,
    Path(id): Path<String>,
    Query(q): Query<ExportQuery>,
    headers: HeaderMap,
) -> Result<Response, Response> {
    let claims = claims_from_auth(&headers)
        .await
        .map_err(IntoResponse::into_response)?;
    if !claims.allows_scope(crate::auth::scope::Scope::Read) {
        return Err(error(StatusCode::FORBIDDEN, "read_scope_required").into_response());
    }
    crate::dataset_routes::authorize_write(&claims).map_err(IntoResponse::into_response)?;
    let policy =
        crate::incident_routes::policy(&state.incident).map_err(IntoResponse::into_response)?;
    crate::incident_routes::check_rate(&state.incident.limiter, &claims.tenant_id, &policy)
        .map_err(IntoResponse::into_response)?;
    crate::dataset_routes::require_datasets(&state.entitlements, &claims.tenant_id)
        .await
        .map_err(IntoResponse::into_response)?;
    let fixture = export_for(&state, &claims.tenant_id, &id, &q)
        .await
        .map_err(IntoResponse::into_response)?;
    Ok((
        [
            (header::CONTENT_TYPE, fixture.content_type),
            (header::CONTENT_DISPOSITION, fixture.disposition),
            (
                header::HeaderName::from_static("x-regression-mode"),
                q.mode.as_str(),
            ),
            (
                header::HeaderName::from_static("x-regression-limits"),
                LIMITS,
            ),
            (
                header::HeaderName::from_static("x-truncated"),
                if fixture.truncated { "true" } else { "false" },
            ),
        ],
        fixture.text,
    )
        .into_response())
}
async fn export_for(
    state: &RegressionState,
    tenant: &tracelane_shared::TenantId,
    id: &str,
    q: &ExportQuery,
) -> Result<Fixture, ApiError> {
    validate_format(&q.format, &q.mode)?;
    let id = uuid::Uuid::parse_str(id)
        .map_err(|_| error(StatusCode::NOT_FOUND, "not_found"))?
        .to_string();
    let spans = state
        .incident
        .store
        .spans(tenant, &id)
        .await
        .map_err(|_| error(StatusCode::BAD_GATEWAY, "regression_read_failed"))?;
    if spans.is_empty() {
        return Err(error(StatusCode::NOT_FOUND, "not_found"));
    }
    if !crate::server::config::content_capture_for(state.entitlements.as_deref(), tenant)
        .await
        .input
    {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"code":"content_not_captured","reason":"content_capture_disabled"})),
        ));
    }
    let cap = state
        .incident
        .rate_card
        .load()
        .policy
        .incident_regression
        .as_ref()
        .map(|p| p.regression_max_cases_per_export)
        .filter(|v| *v > 0)
        .ok_or_else(|| {
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "incident_policy_unavailable",
            )
        })?;
    let rows = state
        .datasets
        .trace_content(tenant, &id, cap + 1)
        .await
        .map_err(|_| error(StatusCode::BAD_GATEWAY, "regression_read_failed"))?;
    let truncated = rows.len() > cap;
    let mut items = vec![];
    for content in rows.into_iter().take(cap) {
        let row = SpanContentRow {
            input_messages: content.input_messages,
            system_instructions: content.system_instructions,
        };
        match crate::dataset_routes::classify_span(Some(row.clone())) {
            SpanVerdict::NoContent => continue,
            SpanVerdict::Unreadable => {
                return Err(error(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "span_content_unreadable",
                ));
            }
            SpanVerdict::NotFound => continue,
            SpanVerdict::Content(_, _) => {}
        }
        items.push(fixture_item(row, &id, &content.span_id, &q.mode, false)?);
    }
    for item in &mut items {
        let mut metadata: Value = serde_json::from_str(&item.metadata).map_err(|_| {
            error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "fixture_serialization_failed",
            )
        })?;
        metadata["truncated"] = json!(truncated);
        item.metadata = metadata.to_string();
    }
    render_fixture(items, &q.format, &q.mode, truncated)
}
fn validate_format(format: &str, mode: &str) -> Result<(), ApiError> {
    if !matches!(mode, "recorded" | "mocked") {
        return Err(error(StatusCode::BAD_REQUEST, "not_supported"));
    }
    if !matches!(format, "dataset" | "promptfoo") {
        return Err(error(StatusCode::BAD_REQUEST, "invalid_format"));
    }
    Ok(())
}
fn fixture_item(
    row: SpanContentRow,
    trace: &str,
    span: &str,
    mode: &str,
    truncated: bool,
) -> Result<DatasetItem, ApiError> {
    let (messages, system) = match crate::dataset_routes::classify_span(Some(row)) {
        SpanVerdict::Content(m, s) => (m, s),
        SpanVerdict::Unreadable => {
            return Err(error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "span_content_unreadable",
            ));
        }
        _ => {
            return Err(error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "content_not_captured",
            ));
        }
    };
    if !system.is_empty()
        && !serde_json::from_str::<Value>(&system).is_ok_and(|v| v.is_string() || v.is_array())
    {
        return Err(error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "span_content_unreadable",
        ));
    }
    let mut item = crate::dataset_routes::trace_item(
        &messages,
        system,
        uuid::Uuid::parse_str(trace).ok(),
        span.to_owned(),
        String::new(),
        0,
    )?;
    item.metadata=json!({"mode":mode,"source_trace_id":trace,"source_span_id":span,"expected_output_reason":"output_not_captured","contains_redactions":item.input.contains("[REDACTED")||item.system.contains("[REDACTED"),"truncated":truncated,"limits":LIMITS,"assertion_required":true}).to_string();
    Ok(item)
}
#[derive(Debug)]
struct Fixture {
    text: String,
    content_type: &'static str,
    disposition: &'static str,
    truncated: bool,
}
fn render_fixture(
    items: Vec<DatasetItem>,
    format: &str,
    mode: &str,
    truncated: bool,
) -> Result<Fixture, ApiError> {
    validate_format(format, mode)?;
    if items.is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(json!({"code":"content_not_captured","reason":"no_recorded_input_messages"})),
        ));
    }
    let (text, content_type, disposition) = if format == "dataset" {
        (
            items
                .iter()
                .map(|i| format!("{}\n", crate::dataset_routes::export_line(i)))
                .collect(),
            "application/x-ndjson",
            "attachment; filename=\"regression.jsonl\"",
        )
    } else {
        let tests:Vec<Value>=items.iter().map(|i|{
            let line=crate::dataset_routes::export_line(i);
            let mut messages=line["input"].as_array().cloned().unwrap_or_default();
            if !line["system"].is_null(){messages.insert(0,json!({"role":"system","content":line["system"]}));}
            json!({"vars":{"input":messages,"system":line["system"]},"assert":[],"metadata":line["metadata"]})
        }).collect();
        (json!({"description":format!("{LIMITS} Configure a provider to replay the model call."),"prompts":["{{ input | dump }}"],"providers":[],"tests":tests}).to_string(),"application/json","attachment; filename=\"regression.promptfoo.json\"")
    };
    Ok(Fixture {
        text,
        content_type,
        disposition,
        truncated,
    })
}
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn af3_regression_export_rejects_missing_auth_and_ingest_only_key() {
        use axum::{
            body::{Body, to_bytes},
            http::Request,
        };
        use tower::ServiceExt;

        let server = wiremock::MockServer::start().await;
        let ch = clickhouse::Client::default().with_url(server.uri());
        let app = routes().with_state(RegressionState {
            incident: IncidentState {
                limiter: Arc::new(crate::rate_limiter::RateLimiter::new()),
                store: Arc::new(crate::incident_routes::ClickHouseIncidentStore {
                    ch: ch.clone(),
                    pg: None,
                }),
                rate_card: Arc::new(arc_swap::ArcSwap::from_pointee(
                    crate::billing::RateCard::unavailable(),
                )),
                outcomes: Arc::new(crate::outcome_routes::ClickHouseOutcomeStore {
                    ch: ch.clone(),
                }),
                entitlements: None,
            },
            datasets: Arc::new(crate::dataset_routes::ClickHouseDatasetStore::new(ch)),
            entitlements: None,
        });
        for (scope, status, code) in [
            (None, StatusCode::UNAUTHORIZED, "unauthorized"),
            (Some("ingest"), StatusCode::FORBIDDEN, "read_scope_required"),
        ] {
            let mut request = Request::get(format!(
                "/v1/traces/{}/regression?format=dataset&mode=recorded",
                uuid::Uuid::from_u128(9)
            ));
            if scope.is_some() {
                request = request.header("authorization", "Bearer test");
            }
            let _guard = scope.map(|scope| {
                let mut claims = crate::auth::dev_stub_claims(crate::auth::AuthMethod::ApiKey);
                claims.key_scope = crate::auth::scope::KeyScope::from_column(Some(&[scope.into()]));
                crate::auth::test_claims::Guard::set(claims)
            });
            let response = app
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), status, "scope: {scope:?}");
            let data: Value =
                serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
                    .unwrap();
            assert_eq!(data["code"], code);
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    fn row_string(bytes: &mut Vec<u8>, value: &str) {
        let mut n = value.len();
        while n >= 128 {
            bytes.push((n as u8) | 128);
            n >>= 7;
        }
        bytes.push(n as u8);
        bytes.extend(value.as_bytes());
    }
    #[tokio::test]
    async fn regression_many_spans_use_one_content_query() {
        let tenant = tracelane_shared::TenantId::from_jwt_claim(uuid::Uuid::from_u128(1));
        let trace = uuid::Uuid::from_u128(2).to_string();
        let server = wiremock::MockServer::start().await;
        let trace_response = trace.clone();
        wiremock::Mock::given(wiremock::matchers::path("/"))
            .respond_with(move |request: &wiremock::Request| {
                let sql = request
                    .url
                    .query_pairs()
                    .find(|(k, _)| k == "query")
                    .unwrap()
                    .1
                    .into_owned();
                let spans = sql.contains("AS start_us");
                let single_content = sql.contains("span_id =");
                let mut bytes = Vec::new();
                let count = if spans {
                    30
                } else if single_content {
                    1
                } else {
                    sql.split(" LIMIT ")
                        .nth(1)
                        .unwrap()
                        .split_whitespace()
                        .next()
                        .unwrap()
                        .parse::<usize>()
                        .unwrap()
                        .min(30)
                };
                for i in 0..count {
                    if !single_content {
                        row_string(&mut bytes, &trace_response);
                        row_string(&mut bytes, &format!("span-{i}"));
                    }
                    if spans {
                        bytes.push(1); // nullable parent = NULL
                        bytes.extend(1_i64.to_le_bytes());
                        bytes.push(1);
                        row_string(&mut bytes, "{}");
                    } else {
                        row_string(
                            &mut bytes,
                            r#"[{"role":"user","content":"captured question"}]"#,
                        );
                        row_string(&mut bytes, "");
                    }
                }
                wiremock::ResponseTemplate::new(200).set_body_bytes(bytes)
            })
            .mount(&server)
            .await;
        let cache = Arc::new(crate::entitlement_cache::EntitlementCache::new(Arc::new(
            |_| {
                Box::pin(async {
                    let mut e = crate::entitlement_cache::ResolvedEntitlements::deny_all();
                    e.content_capture.input = true;
                    Ok(e)
                })
            },
        )));
        let ch = clickhouse::Client::default()
            .with_url(server.uri())
            .with_compression(clickhouse::Compression::None);
        let state = RegressionState {
            incident: IncidentState {
                limiter: Arc::new(crate::rate_limiter::RateLimiter::new()),
                store: Arc::new(crate::incident_routes::ClickHouseIncidentStore {
                    ch: ch.clone(),
                    pg: None,
                }),
                rate_card: Arc::new(arc_swap::ArcSwap::from_pointee(
                    crate::billing::RateCard::unavailable(),
                )),
                outcomes: Arc::new(crate::outcome_routes::ClickHouseOutcomeStore {
                    ch: ch.clone(),
                }),
                entitlements: Some(cache.clone()),
            },
            datasets: Arc::new(crate::dataset_routes::ClickHouseDatasetStore::new(ch)),
            entitlements: Some(cache),
        };
        let fixture = export_for(
            &state,
            &tenant,
            &trace,
            &ExportQuery {
                format: "dataset".into(),
                mode: "recorded".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(fixture.text.lines().count(), 30);
        let requests = server.received_requests().await.unwrap();
        assert_eq!(
            requests.len(),
            2,
            "one trace existence read and one content read, independent of span count"
        );
        let sql = requests[1]
            .url
            .query_pairs()
            .find(|(k, _)| k == "query")
            .unwrap()
            .1
            .into_owned();
        assert!(
            sql.contains(&format!(
                "WHERE tenant_id = '{tenant}' AND trace_id = '{trace}' AND JSONHas"
            )),
            "{sql}"
        );
        let cap = crate::incident_routes::IncidentPolicy::embedded()
            .unwrap()
            .regression_max_cases_per_export;
        assert!(sql.contains(&format!("LIMIT {}", cap + 1)), "{sql}");
        let mut card = (**state.incident.rate_card.load()).clone();
        card.policy
            .incident_regression
            .as_mut()
            .unwrap()
            .regression_max_cases_per_export = 3;
        state.incident.rate_card.store(Arc::new(card));
        let limited = export_for(
            &state,
            &tenant,
            &trace,
            &ExportQuery {
                format: "dataset".into(),
                mode: "mocked".into(),
            },
        )
        .await
        .unwrap();
        assert_eq!(limited.text.lines().count(), 3);
        assert!(limited.truncated);
        for line in limited.text.lines() {
            let item: Value = serde_json::from_str(line).unwrap();
            assert_eq!(item["metadata"]["truncated"], true);
            assert_eq!(item["metadata"]["mode"], "mocked");
        }
        assert_eq!(server.received_requests().await.unwrap().len(), 4);
    }

    #[test]
    fn regression_empty_content_is_422_and_live_is_never_exported() {
        let e = render_fixture(vec![], "dataset", "recorded", false).unwrap_err();
        assert_eq!(e.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(e.1.0["code"], "content_not_captured");
        assert_eq!(
            render_fixture(vec![], "dataset", "live", false)
                .unwrap_err()
                .0,
            StatusCode::BAD_REQUEST
        );
    }
    #[test]
    fn regression_dataset_matches_existing_export_line_and_preserves_null_output() {
        let input = serde_json::json!([{"role":"user","content":"test question"}]).to_string();
        let row = crate::dataset_routes::SpanContentRow {
            input_messages: input,
            system_instructions: String::new(),
        };
        let item = fixture_item(row, "trace", "span", "mocked", false).unwrap();
        let response = render_fixture(vec![item.clone()], "dataset", "mocked", false).unwrap();
        assert_eq!(
            response.text,
            format!("{}\n", crate::dataset_routes::export_line(&item))
        );
        let value: Value = serde_json::from_str(response.text.trim()).unwrap();
        assert!(value["expected_output"].is_null());
        assert_eq!(value["metadata"]["mode"], "mocked");
        assert_eq!(
            value["metadata"]["expected_output_reason"],
            "output_not_captured"
        );
    }
    #[test]
    fn regression_promptfoo_matches_upstream_schema_fixture() {
        let input = json!([{"role":"user","content":"test question"}]).to_string();
        let item = fixture_item(
            crate::dataset_routes::SpanContentRow {
                input_messages: input,
                system_instructions: String::new(),
            },
            "trace",
            "span",
            "recorded",
            false,
        )
        .unwrap();
        let response = render_fixture(vec![item], "promptfoo", "recorded", false).unwrap();
        let actual: Value = serde_json::from_str(&response.text).unwrap();
        let expected: Value =
            serde_json::from_str(include_str!("../tests/fixtures/regression-promptfoo.json"))
                .unwrap();
        assert_eq!(
            actual, expected,
            "the same fixture is validated against the upstream schema by the web test suite"
        );
    }
    #[test]
    fn regression_mocked_preserves_tool_history_system_and_redaction_markers() {
        let input = json!([
            {"role":"user","content":"[REDACTED:email]"},
            {"role":"tool","content":"fixed result","tool_call_id":"call1"}
        ])
        .to_string();
        let row = SpanContentRow {
            input_messages: input,
            system_instructions: json!("Keep it short").to_string(),
        };
        let item = fixture_item(row, "trace", "span", "mocked", true).unwrap();
        let metadata: Value = serde_json::from_str(&item.metadata).unwrap();
        assert_eq!(metadata["contains_redactions"], true);
        assert_eq!(metadata["truncated"], true);
        let fixture = render_fixture(vec![item], "promptfoo", "mocked", true).unwrap();
        let value: Value = serde_json::from_str(&fixture.text).unwrap();
        assert_eq!(value["tests"][0]["vars"]["input"][0]["role"], "system");
        assert_eq!(value["tests"][0]["vars"]["input"][2]["role"], "tool");
        assert!(fixture.truncated);
        assert!(value["providers"].as_array().unwrap().is_empty());
    }
    #[test]
    fn regression_unresolved_system_blob_is_never_an_empty_system_prompt() {
        let row = SpanContentRow {
            input_messages: json!([{"role":"user","content":"hi"}]).to_string(),
            system_instructions: json!({"$ref":"unresolved"}).to_string(),
        };
        assert_eq!(
            fixture_item(row, "trace", "span", "recorded", false)
                .unwrap_err()
                .1
                .0["code"],
            "span_content_unreadable"
        );
    }
}
